package framework

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	configv1 "github.com/openshift/api/config/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
)

// TestPool is one isolated MachineConfigPool "lane" that a destructive serial
// test runs against. Each lane owns a distinct worker node and its own pair of
// ScanSettings, so the reboot-heavy tests can execute in parallel without
// contending on a single shared pool/node.
type TestPool struct {
	Index                int
	Name                 string
	DefaultScanSetting   string
	AutoApplyScanSetting string
}

// NodeRoleSelector returns the node selector matching this lane's single node.
func (p *TestPool) NodeRoleSelector() map[string]string {
	return utils.GetNodeRoleSelector(p.Name)
}

// laneTestMinutes is how long each lane test takes (measured on a 4.21 GCP
// cluster, 2026-10-06). When there are more lane tests than lanes, a free lane
// goes to the longest waiting test first, so the slowest test doesn't start
// last and stretch the run. Tests missing here count as 0 and run last.
var laneTestMinutes = map[string]int{
	"TestRuntimeSSHConfigWithRemediation": 15,
	"TestUnapplyRemediation":              11,
	"TestUpdateRemediation":               10,
	"TestAutoRemediate":                   9,
	"TestKubeletConfigRemediation":        7,
}

// laneQueue hands out lanes to waiting tests, longest test first.
type laneQueue struct {
	mu      sync.Mutex
	free    []*TestPool
	waiters []*laneWaiter
	// ready is closed when the first lane is put, for finishTestPools.
	ready     chan struct{}
	readyOnce sync.Once
}

type laneWaiter struct {
	minutes int
	lane    chan *TestPool
}

func newLaneQueue() *laneQueue {
	return &laneQueue{ready: make(chan struct{})}
}

// put makes lane p available: it goes straight to the longest waiting test, or
// into the free list when nobody is waiting.
func (q *laneQueue) put(p *TestPool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.readyOnce.Do(func() { close(q.ready) })
	if len(q.waiters) == 0 {
		q.free = append(q.free, p)
		return
	}
	w := q.waiters[0]
	q.waiters = q.waiters[1:]
	w.lane <- p
}

// get returns a free lane right away, or queues the caller by test duration
// and returns the channel its lane will arrive on.
func (q *laneQueue) get(minutes int) (*TestPool, chan *TestPool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.free) > 0 {
		p := q.free[0]
		q.free = q.free[1:]
		return p, nil
	}
	w := &laneWaiter{minutes: minutes, lane: make(chan *TestPool, 1)}
	q.waiters = append(q.waiters, w)
	sort.SliceStable(q.waiters, func(i, j int) bool { return q.waiters[i].minutes > q.waiters[j].minutes })
	return nil, w.lane
}

// testPoolCount is the number of parallel destructive lanes to set up. It
// defaults to 1 (a single "e2e" pool, identical to the historical behavior, so
// non-serial suites that share SetUp are unaffected) and is raised to N via
// E2E_PARALLEL_POOLS - the serial suite's Makefile target sets it. setUpTestPools
// caps it at the number of available worker nodes.
func testPoolCount() int {
	if v := os.Getenv("E2E_PARALLEL_POOLS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
		log.Printf("ignoring invalid E2E_PARALLEL_POOLS=%q; using default", v)
	}
	return 1
}

// startTestPools carves one MachineConfigPool lane per worker node (up to
// testPoolCount). It labels the lane nodes and creates all the pools up front,
// then waits for MCO to roll the nodes into them in the background: MCO updates
// distinct pools concurrently, so the whole set takes about as long as one pool.
// SetUp calls this before deploying the operator so the wait overlaps with the
// deployment and ProfileBundle parsing; finishTestPools joins it. We reuse the
// existing worker nodes rather than scaling the cluster; when every worker
// becomes a lane the operator still runs (nodes keep their worker label) but has
// no idle worker to fall back to during simultaneous reboots.
func (f *Framework) startTestPools() error {
	if f.Platform == "rosa" {
		fmt.Printf("bypassing test pool setup because MachineConfigPools are not supported on %s\n", f.Platform)
		f.TestPools = newLaneQueue()
		return nil
	}

	nodes, err := f.getWorkerNodes()
	if err != nil {
		return fmt.Errorf("failed to list worker nodes for test pools: %w", err)
	}

	n := testPoolCount()
	// Keep one worker out of the lanes when there's more than one, so pods
	// evicted while a lane reboots (router, registry, monitoring) have somewhere
	// to go instead of holding up the drain. When the masters are schedulable
	// they take those pods, so every worker can be a lane. Lane scans only
	// select their own lane role, so they never run on the masters.
	maxLanes := len(nodes)
	if maxLanes > 1 && !f.mastersSchedulable() {
		maxLanes--
	}
	if n > maxLanes {
		log.Printf("E2E_PARALLEL_POOLS=%d exceeds the %d worker nodes available for lanes (one of %d stays free for evicted pods); capping to %d", n, maxLanes, len(nodes), maxLanes)
		n = maxLanes
	}
	if n < 1 {
		return fmt.Errorf("no worker nodes available to create test pools")
	}

	f.testPoolNames = nil
	f.testPoolNodes = nil
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("%s-%d", TestPoolName, i)
		if n == 1 {
			// Preserve the historical single-pool name "e2e" (and "e2e-default"
			// ScanSettings) when not sharding, so suites that share SetUp but
			// don't run in parallel behave exactly as before.
			name = TestPoolName
		}
		if err := f.createMachineConfigPoolForNode(name, &nodes[i]); err != nil {
			return fmt.Errorf("failed to create test pool %s: %w", name, err)
		}
		f.testPoolNames = append(f.testPoolNames, name)
		f.testPoolNodes = append(f.testPoolNodes, nodes[i].Name)
	}

	// Hand each lane out as soon as it's ready, so tests start once any lane is
	// available instead of waiting for all of them. A lane's ScanSettings copy
	// the operator's defaults, so they're created after finishTestPools reports
	// the operator is up.
	f.TestPools = newLaneQueue()
	f.testPoolErrs = make(chan error, n)
	f.operatorReady = make(chan struct{})
	for i, name := range f.testPoolNames {
		go f.readyTestPool(i, name, f.testPoolNodes[i])
	}
	return nil
}

// mastersSchedulable reports whether the cluster scheduler lets ordinary pods
// run on the control plane (schedulers.config.openshift.io/cluster).
func (f *Framework) mastersSchedulable() bool {
	s := &configv1.Scheduler{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: "cluster"}, s); err != nil {
		log.Printf("couldn't read the cluster Scheduler config, assuming masters aren't schedulable: %s", err)
		return false
	}
	return s.Spec.MastersSchedulable
}

// readyTestPool waits for lane i's pool to roll out, creates the lane's
// ScanSettings once the operator is up, and hands the lane out via TestPools.
func (f *Framework) readyTestPool(i int, name, node string) {
	start := time.Now()
	if err := f.waitForMachineConfigPoolUpdated(name); err != nil {
		f.testPoolErrs <- fmt.Errorf("failed to create test pool %s: %w", name, err)
		return
	}
	<-f.operatorReady
	if err := f.ensureE2EScanSettingsForPool(name); err != nil {
		f.testPoolErrs <- fmt.Errorf("failed to create scan settings for test pool %s: %w", name, err)
		return
	}
	f.TestPools.put(&TestPool{
		Index:                i,
		Name:                 name,
		DefaultScanSetting:   name + "-default",
		AutoApplyScanSetting: name + "-default-auto-apply",
	})
	log.Printf("test pool lane %d ready on node %s: %s (%s after creation)", i, node, name, time.Since(start).Round(time.Second))
}

// finishTestPools tells the lanes started by startTestPools that the operator is
// up, so they can create their ScanSettings. It doesn't wait for the lanes:
// tests block in AcquireTestPool until one is ready. With a single lane (suites
// that don't shard), it waits for that lane, so its "e2e-default" ScanSettings
// exist before any test runs, as before.
func (f *Framework) finishTestPools() error {
	if f.operatorReady == nil {
		if f.Platform == "rosa" {
			return nil
		}
		return fmt.Errorf("finishTestPools called before startTestPools")
	}
	close(f.operatorReady)
	if len(f.testPoolNames) != 1 {
		return nil
	}
	select {
	case <-f.TestPools.ready:
		return nil
	case err := <-f.testPoolErrs:
		return err
	}
}

// AcquireTestPool checks out an isolated pool lane for a destructive test,
// blocking until one is free, and returns it when the test ends. Call
// t.Parallel() before this so lanes are shared across concurrent tests. Waiting
// tests get lanes longest first (laneTestMinutes).
func (f *Framework) AcquireTestPool(t *testing.T) *TestPool {
	t.Helper()
	p, wait := f.TestPools.get(laneTestMinutes[t.Name()])
	if p == nil {
		select {
		case p = <-wait:
		case err := <-f.testPoolErrs:
			f.testPoolErrs <- err // let other waiting tests see it too
			t.Fatalf("no test pool lane available: %s", err)
		}
	}
	t.Logf("acquired test pool lane %s", p.Name)
	t.Cleanup(func() {
		f.TestPools.put(p)
		t.Logf("released test pool lane %s", p.Name)
	})
	return p
}

// tearDownTestPools deletes the per-lane ScanSettings. It intentionally does NOT
// restore node labels or delete the MachineConfigPools: that would reboot every
// lane node back to rendered-worker, and the CI cluster is destroyed right after
// the run, so the work would be wasted.
func (f *Framework) tearDownTestPools() error {
	if f.Platform == "rosa" {
		return nil
	}
	for _, name := range f.testPoolNames {
		for _, suffix := range []string{"-default", "-default-auto-apply"} {
			if err := f.deleteScanSettings(name + suffix); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		}
	}
	return nil
}
