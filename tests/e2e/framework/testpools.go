package framework

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
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
		f.TestPools = make(chan *TestPool, 1)
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
	f.TestPools = make(chan *TestPool, n)
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
	f.TestPools <- &TestPool{
		Index:                i,
		Name:                 name,
		DefaultScanSetting:   name + "-default",
		AutoApplyScanSetting: name + "-default-auto-apply",
	}
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
	case p := <-f.TestPools:
		f.TestPools <- p
		return nil
	case err := <-f.testPoolErrs:
		return err
	}
}

// AcquireTestPool checks out an isolated pool lane for a destructive test,
// blocking until one is free, and returns it when the test ends. Call
// t.Parallel() before this so lanes are shared across concurrent tests.
func (f *Framework) AcquireTestPool(t *testing.T) *TestPool {
	t.Helper()
	var p *TestPool
	select {
	case p = <-f.TestPools:
	default:
		select {
		case p = <-f.TestPools:
		case err := <-f.testPoolErrs:
			f.testPoolErrs <- err // let other waiting tests see it too
			t.Fatalf("no test pool lane available: %s", err)
		}
	}
	t.Logf("acquired test pool lane %s", p.Name)
	t.Cleanup(func() {
		f.TestPools <- p
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
