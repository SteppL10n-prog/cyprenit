// TEST-01 — Ring Buffer Consumer Deadlock Yok (backpressure / non-blocking).
// Contract: Submit() NEVER blocks; when the consumer is slow/dead records drop and
// ARE COUNTED (no silent loss); Close() returns without deadlock; no goroutine leak.
package ring_test

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SteppL10n-prog/cyprenit/internal/abi"
	"github.com/SteppL10n-prog/cyprenit/internal/parser"
	"github.com/SteppL10n-prog/cyprenit/internal/ring"
)

// frame builds a valid ABI-encoded event exactly like the kernel probe would.
func frame(t *testing.T, cookie uint32, payload []byte) []byte {
	t.Helper()
	buf := make([]byte, abi.EventSize)
	e := &abi.Event{
		TimestampNS: 1, PidTgid: 2 << 16,
		Saddr: [4]byte{10, 0, 0, 1}, Daddr: [4]byte{10, 0, 0, 2},
		Sport: 1234, Dport: 443, Direction: abi.DirEgress,
		HSType: abi.HSClientHello, TLSVersion: 0x0303,
		Cookie: cookie, Payload: payload,
	}
	if err := e.Encode(buf); err != nil {
		t.Fatalf("encode: %v", err)
	}
	return buf
}

// blockingSink simulates the worst-case wedged consumer: it parks inside the
// sink forever. A correct pipeline must degrade to drops + counters, never
// propagate back-pressure into Submit(), and still Close() cleanly.
func TestTEST01_SubmitNeverBlocksUnderSaturation(t *testing.T) {
	base := runtime.NumGoroutine()

	var parked atomic.Bool
	release := make(chan struct{})
	p := ring.NewPipeline(2, 4, func(rec *parser.ParsedRecord) {
		if parked.CompareAndSwap(false, true) {
			<-release // first record wedges the sink forever
		}
	})

	f := frame(t, 7, []byte{0x16, 0x03, 0x01})
	const n = 5000
	errs := make(chan error, n)
	start := time.Now()
	var wg sync.WaitGroup
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < n/50; i++ {
				errs <- p.Submit(f) // contract: returns immediately
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("TEST-01 FAIL: Submit blocked — deadlock/backpressure leak")
	}
	elapsed := time.Since(start)

	var full int
	close(errs)
	for err := range errs {
		switch {
		case err == nil, errors.Is(err, ring.ErrFull):
			if err != nil {
				full++
			}
		default:
			close(release)
			t.Fatalf("beklenmeyen hata: %v", err)
		}
	}
	sub, over, _, _, _, _ := p.Snapshot()
	if sub != int64(n) {
		t.Fatalf("submitted=%d, want %d", sub, n)
	}
	if over != int64(full) {
		t.Fatalf("overflow counter %d != expected drops %d (unmeasured loss = silent data loss)", over, full)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("total Submit duration %v — non-blocking contract violation", elapsed)
	}

	// Shutdown: because of the wedged sink Close may exceed its deadline -> Close
	// returning an error is better than a wedge; but the test does not tolerate
	// that either — we free the sink first (a real watchdog does the same).
	close(release)
	if err := p.Close(5 * time.Second); err != nil {
		t.Fatalf("TEST-01 FAIL: Close deadlock: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if leaked := runtime.NumGoroutine() - base; leaked > 8 {
		t.Fatalf("goroutine leak: +%d", leaked)
	}
}

func TestTEST01_RejectsShortFramesWithoutBlocking(t *testing.T) {
	p := ring.NewPipeline(1, 8, nil)
	defer func() { _ = p.Close(time.Second) }()
	if err := p.Submit(make([]byte, abi.EventSize-1)); !errors.Is(err, ring.ErrShort) {
		t.Fatalf("short frame must return ErrShort, got: %v", err)
	}
}
