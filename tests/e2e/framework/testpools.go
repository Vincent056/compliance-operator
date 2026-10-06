package framework

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
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
	f.testPoolsReady = make(chan error, 1)
	if f.Platform == "rosa" {
		fmt.Printf("bypassing test pool setup because MachineConfigPools are not supported on %s\n", f.Platform)
		f.testPoolsReady <- nil
		return nil
	}

	nodes, err := f.getWorkerNodes()
	if err != nil {
		return fmt.Errorf("failed to list worker nodes for test pools: %w", err)
	}

	n := testPoolCount()
	if n > len(nodes) {
		log.Printf("E2E_PARALLEL_POOLS=%d exceeds available worker nodes (%d); capping to %d", n, len(nodes), len(nodes))
		n = len(nodes)
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

	names := append([]string(nil), f.testPoolNames...)
	go func() {
		start := time.Now()
		for _, name := range names {
			if err := f.waitForMachineConfigPoolUpdated(name); err != nil {
				f.testPoolsReady <- fmt.Errorf("failed to create test pool %s: %w", name, err)
				return
			}
		}
		log.Printf("all %d test pool lanes updated %s after creation", len(names), time.Since(start).Round(time.Second))
		f.testPoolsReady <- nil
	}()
	return nil
}

// finishTestPools waits for the lane pools started by startTestPools, then
// creates each lane's ScanSettings and hands the lanes out via TestPools. The
// ScanSettings are copies of the operator's defaults, so this has to run after
// the operator is up.
func (f *Framework) finishTestPools() error {
	if f.testPoolsReady == nil {
		return fmt.Errorf("finishTestPools called before startTestPools")
	}
	if err := <-f.testPoolsReady; err != nil {
		return err
	}
	if f.Platform == "rosa" {
		f.TestPools = make(chan *TestPool, 1)
		return nil
	}

	f.TestPools = make(chan *TestPool, len(f.testPoolNames))
	for i, name := range f.testPoolNames {
		if err := f.ensureE2EScanSettingsForPool(name); err != nil {
			return fmt.Errorf("failed to create scan settings for test pool %s: %w", name, err)
		}
		f.TestPools <- &TestPool{
			Index:                i,
			Name:                 name,
			DefaultScanSetting:   name + "-default",
			AutoApplyScanSetting: name + "-default-auto-apply",
		}
		log.Printf("test pool lane %d ready on node %s: %s", i, f.testPoolNodes[i], name)
	}
	return nil
}

// AcquireTestPool checks out an isolated pool lane for a destructive test,
// blocking until one is free, and returns it when the test ends. Call
// t.Parallel() before this so lanes are shared across concurrent tests.
func (f *Framework) AcquireTestPool(t *testing.T) *TestPool {
	t.Helper()
	p := <-f.TestPools
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
			if err := f.deleteScanSettings(name + suffix); err != nil {
				return err
			}
		}
	}
	return nil
}
