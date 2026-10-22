package framework

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
)

// SpareRole is the node role given to the workers kept out of the lanes. The
// parallel scan tests scan those workers (WorkerScanRole) instead of every
// worker, so they never scan a lane node that a remediation test reboots.
const SpareRole = "e2e-spare"

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

// laneQueue hands out lanes to waiting tests in the order they asked.
type laneQueue struct {
	mu      sync.Mutex
	free    []*TestPool
	waiters []chan *TestPool
	// ready is closed when the first lane is put, for finishTestPools.
	ready     chan struct{}
	readyOnce sync.Once
}

func newLaneQueue() *laneQueue {
	return &laneQueue{ready: make(chan struct{})}
}

// put makes lane p available: it goes straight to the first waiting test, or
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
	w <- p
}

// get returns a free lane right away, or queues the caller and returns the
// channel its lane will arrive on.
func (q *laneQueue) get() (*TestPool, chan *TestPool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.free) > 0 {
		p := q.free[0]
		q.free = q.free[1:]
		return p, nil
	}
	w := make(chan *TestPool, 1)
	q.waiters = append(q.waiters, w)
	return nil, w
}

// WithTestPools makes SetUp shard the e2e pool into lanes, for a suite whose
// destructive tests take one with AcquireTestPool. Suites without it get the
// single "e2e" pool, set up and torn down as before.
func WithTestPools() Option {
	return func(f *Framework) { f.useTestPools = true }
}

// testPoolCount is the number of lanes to set up. It defaults to 1, a single
// pool named "e2e" like the one suites without lanes get, and
// E2E_PARALLEL_POOLS raises it; the serial suite's Makefile target sets it.
// startTestPools caps it at the worker nodes available.
func testPoolCount() int {
	if v := os.Getenv("E2E_PARALLEL_POOLS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
		log.Printf("ignoring invalid E2E_PARALLEL_POOLS=%q; using default", v)
	}
	return 1
}

// startTestPools carves one MachineConfigPool lane per worker node, up to
// testPoolCount, and keeps one worker out of the lanes as a spare. It labels
// the lane nodes and creates all the pools up front, then waits for MCO to roll
// the nodes into them in the background: MCO updates distinct pools
// concurrently, so the whole set takes about as long as one pool. SetUp calls
// this before deploying the operator so the wait overlaps with the deployment
// and ProfileBundle parsing; finishTestPools joins it. The cluster must already
// have the workers: CI provisions a worker per lane plus the spare
// (COMPUTE_NODE_REPLICAS in the e2e-aws-serial job).
func (f *Framework) startTestPools() error {
	if f.Platform == "rosa" {
		fmt.Printf("bypassing test pool setup because MachineConfigPools are not supported on %s\n", f.Platform)
		return nil
	}

	nodes, err := f.getWorkerNodes()
	if err != nil {
		return fmt.Errorf("failed to list worker nodes for test pools: %w", err)
	}
	if len(nodes) == 0 {
		return fmt.Errorf("no worker nodes available to create test pools")
	}

	// Keep one worker out of the lanes when there's more than one. Pods
	// evicted while a lane reboots (router, registry, monitoring) need
	// somewhere to go, and the parallel scan tests scan the spare workers
	// (SpareRole) instead of the lane nodes.
	maxLanes := len(nodes)
	if maxLanes > 1 {
		maxLanes--
	}
	lanes := testPoolCount()
	if lanes > maxLanes {
		log.Printf("E2E_PARALLEL_POOLS=%d needs %d workers, a lane each plus a spare, and the cluster has %d; capping the lanes to %d", lanes, lanes+1, len(nodes), maxLanes)
		lanes = maxLanes
	}

	f.testPoolNames = nil
	for i := 0; i < lanes; i++ {
		name := fmt.Sprintf("%s-%d", TestPoolName, i)
		if lanes == 1 {
			// A single lane keeps the name "e2e" and the "e2e-default"
			// ScanSettings, like the pool suites without lanes get.
			name = TestPoolName
		}
		f.testPoolNames = append(f.testPoolNames, name)
	}

	// Hand each lane out as soon as it's ready, so tests start once any lane is
	// available instead of waiting for all of them. A lane's ScanSettings copy
	// the operator's defaults, so they're created after finishTestPools reports
	// the operator is up.
	f.TestPools = newLaneQueue()
	f.testPoolErrs = make(chan error, lanes)
	f.operatorReady = make(chan struct{})
	for i, name := range f.testPoolNames {
		if err := f.createMachineConfigPoolForNode(name, &nodes[i]); err != nil {
			return fmt.Errorf("failed to create test pool %s: %w", name, err)
		}
		go f.readyTestPool(i, name, nodes[i].Name)
	}
	if lanes > 1 {
		return f.labelSpareWorkers(nodes[lanes:])
	}
	return nil
}

// waitForNodeOnPoolConfig waits until the node runs the pool's current
// rendered config, for example after it left a lane pool.
func (f *Framework) waitForNodeOnPoolConfig(nodeName, pool string) error {
	start := time.Now()
	err := wait.PollImmediate(machineOperationRetryInterval, machineOperationTimeout, func() (bool, error) {
		mcp := &mcfgv1.MachineConfigPool{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: pool}, mcp); err != nil {
			return false, nil
		}
		node := &corev1.Node{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: nodeName}, node); err != nil {
			return false, nil
		}
		a := node.GetAnnotations()
		want := mcp.Spec.Configuration.Name
		return want != "" && a["machineconfiguration.openshift.io/currentConfig"] == want &&
			a["machineconfiguration.openshift.io/desiredConfig"] == want &&
			a["machineconfiguration.openshift.io/state"] == "Done", nil
	})
	if err != nil {
		return fmt.Errorf("node %s did not move to pool %s's config: %w", nodeName, pool, err)
	}
	log.Printf("node %s runs pool %s's config (%s)", nodeName, pool, time.Since(start).Round(time.Second))
	return nil
}

// labelSpareWorkers gives the spare workers the SpareRole label, removing any
// lane label an earlier run on the same cluster left on them. (Lane nodes lose
// a stale SpareRole label when they get their lane label.)
func (f *Framework) labelSpareWorkers(spares []corev1.Node) error {
	label := "node-role.kubernetes.io/" + SpareRole
	for i := range spares {
		removedStale, err := f.setPoolRoleLabel(&spares[i], label)
		if err != nil {
			return fmt.Errorf("failed to label spare worker %s: %w", spares[i].Name, err)
		}
		if removedStale {
			// It was in a lane pool; let MCO move it back to the worker pool
			// before scan tests use it.
			if err := f.waitForNodeOnPoolConfig(spares[i].Name, "worker"); err != nil {
				return err
			}
		}
		log.Printf("spare worker %s gets role %s for the parallel scan tests", spares[i].Name, SpareRole)
	}
	f.haveSpares = len(spares) > 0
	return nil
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
// tests block in AcquireTestPool until one is ready. With a single lane it
// waits for that lane, so its "e2e-default" ScanSettings exist before any test
// runs, as they do in suites without lanes.
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
// tests get lanes in the order they asked.
func (f *Framework) AcquireTestPool(t *testing.T) *TestPool {
	t.Helper()
	if f.TestPools == nil {
		t.Fatal("no test pool lanes: the suite needs framework.NewFramework(framework.WithTestPools()), SKIP_MCP_SETUP must be unset, and rosa has no MachineConfigPools for them")
	}
	p, wait := f.TestPools.get()
	if p == nil {
		select {
		case p = <-wait:
		case err := <-f.testPoolErrs:
			f.testPoolErrs <- err // let other waiting tests see it too
			t.Fatalf("no test pool lane available: %s", err)
		}
	}
	t.Logf("acquired test pool lane %s", p.Name)
	acquired := time.Now()
	t.Cleanup(func() {
		f.TestPools.put(p)
		t.Logf("released test pool lane %s after %s", p.Name, time.Since(acquired).Round(time.Second))
	})
	return p
}

// tearDownTestPools deletes the lanes' ScanSettings. With -restoreTestPools it
// also moves the lane nodes back to the worker pool, deletes the lane pools and
// takes the spare role off the spare workers, for a cluster you keep. CI
// doesn't set it: the cluster is discarded after the run, so moving every lane
// node back to the worker pool's config would be wasted time.
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
	if !f.restoreTestPools {
		return nil
	}
	for _, name := range f.testPoolNames {
		if err := f.removeTestPool(name); err != nil {
			return err
		}
	}
	spareLabel := "node-role.kubernetes.io/" + SpareRole
	spares, err := f.GetNodesWithSelector(map[string]string{spareLabel: ""})
	if err != nil {
		return fmt.Errorf("failed to list the spare workers: %w", err)
	}
	for i := range spares {
		if err := f.patchNodeLabel(spares[i].Name, spareLabel, nil); err != nil {
			return fmt.Errorf("failed to take role %s off node %s: %w", SpareRole, spares[i].Name, err)
		}
	}
	return nil
}

// removeTestPool moves lane name's node back to the worker pool and deletes the
// lane's pool. It waits until the node runs the worker pool's config first:
// deleting a pool deletes its rendered config, and a node still running that
// config goes Degraded.
func (f *Framework) removeTestPool(name string) error {
	label := "node-role.kubernetes.io/" + name
	nodes, err := f.GetNodesWithSelector(map[string]string{label: ""})
	if err != nil {
		return fmt.Errorf("failed to list the nodes in test pool %s: %w", name, err)
	}
	for i := range nodes {
		if err := f.patchNodeLabel(nodes[i].Name, label, nil); err != nil {
			return fmt.Errorf("failed to take node %s out of test pool %s: %w", nodes[i].Name, name, err)
		}
	}
	for i := range nodes {
		if err := f.waitForNodeOnPoolConfig(nodes[i].Name, "worker"); err != nil {
			return err
		}
	}
	pool := &mcfgv1.MachineConfigPool{}
	pool.SetName(name)
	if err := f.Client.Delete(context.TODO(), pool); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete test pool %s: %w", name, err)
	}
	log.Printf("removed test pool %s", name)
	return nil
}
