// TEST-02 — Memory Leak: the ParsedRecord pool must return every record fully
// per release; in-use must reach 0 at shutdown and the leak detector must not be blind.
//
// NOTE: the pool is package-level shared state (like the real daemon). Therefore
// tests that VERIFY counters do NOT use t.Parallel(); concurrently running
// tests' instantaneous in-use values would break these assertions (false
// positives). The idempotent Release contract holds under all conditions.
package parser_test

import (
	"sync"
	"testing"

	"github.com/SteppL10n-prog/cyprenit/internal/parser"
	"github.com/SteppL10n-prog/cyprenit/internal/testdata"
)

func TestTEST02_PoolNoLeakOnFullRelease(t *testing.T) {
	const n = 10000
	baseGets, basePuts := getsPuts()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < n/8; i++ {
				rec, err := parser.Handshake(testdata.RSAClientHello[5:],
					uint32(i), uint32(g)<<16,
					[4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1000, 443, 0x0303, 0)
				if err != nil {
					t.Errorf("handshake: %v", err)
					return
				}
				_ = rec.Kind // consume
				rec.Release()
				rec.Release() // double release must be idempotent and never corrupt counters
			}
		}(g)
	}
	wg.Wait()

	_, _, gets, puts := parser.Stats()
	dg, dp := gets-baseGets, puts-basePuts
	// Exact counter audit: 8 goroutines x n/8 = n gets and exactly n puts by CAS design.
	// With no parallel-test noise this must match one-to-one;
	// any deviation means double releases are counted or a release is missing.
	if dg != n || dp != n {
		t.Fatalf("gets+%d puts+%d, want +%d/%d — double Release or missing Release", dg, dp, n, n)
	}
}

func getsPuts() (int64, int64) {
	_, _, g, p := parser.Stats()
	return g, p
}

func TestTEST02_LeakDetectorDetectsUnreleasedRecords(t *testing.T) {
	// Delta-based audit: because the pool is package-level shared state, absolute
	// "0" values are not asserted; only this test's own delta is measured. An intentional leak
	// MUST be visible to the detector; the delta must reset after idempotent Release.
	base := leaked(t)
	var held []*parser.ParsedRecord
	for i := 0; i < 100; i++ {
		rec, _ := parser.Handshake(testdata.ECCClientHello[5:],
			uint32(i), 1<<16, [4]byte{1}, [4]byte{2}, 1, 443, 0x0303, 0)
		held = append(held, rec) // NO Release — intentional leak
	}
	if got := leaked(t) - base; got != 100 {
		t.Fatalf("leak detector saw delta %d, want 100 — unreliable detector!", got)
	}
	for _, r := range held {
		r.Release()
		r.Release() // double release must be idempotent — it MUST NOT decrement counters
	}
	if got := leaked(t) - base; got != 0 {
		t.Fatalf("delta after double-release=%d, want 0 — double Release corrupts the leak counter", got)
	}
}

func leaked(t *testing.T) int64 {
	t.Helper()
	inUse, _, _, _ := parser.Stats()
	return inUse
}
