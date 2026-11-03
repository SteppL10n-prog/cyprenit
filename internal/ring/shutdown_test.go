// TEST-05 — Concurrent Stress & Graceful Shutdown (Panic Isolation).
// Contract: 1000 events x N workers; a panicking sink MUST NOT kill the pipeline;
// after Close, Submit returns ErrClosed without blocking; double Close is idempotent.
package ring_test

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SteppL10n-prog/cyprenit/internal/abi"
	"github.com/SteppL10n-prog/cyprenit/internal/parser"
	"github.com/SteppL10n-prog/cyprenit/internal/ring"
	"github.com/SteppL10n-prog/cyprenit/internal/testdata"
)

func TestTEST05_StressWithPoisonSinkAndGracefulShutdown(t *testing.T) {
	var seen atomic.Int64
	p := ring.NewPipeline(8, 1024, func(rec *parser.ParsedRecord) {
		// Sink contract: rec is a read-only view; ownership and Release
		// belong to the pipeline (Release from the sink side is a no-op — epoch 0).
		seen.Add(1)
		if rec.Dport == 9999 { // poison record: try to kill the sink
			panic("poison payload")
		}
	})

	const n = 1000
	const poison = 20
	for i := 0; i < n; i++ {
		dport := uint16(443)
		payload := testdata.ECCClientHello[5:]
		if i < poison {
			dport = 9999 // first 20 records are poisoned
			payload = testdata.RSAClientHello[5:]
		}
		buf := frameWithPort(t, uint32(i), payload[:min(len(payload), abi.PayloadMax)], dport)
		if err := p.Submit(buf); err != nil {
			t.Fatalf("stress submit[%d]: %v", i, err)
		}
	}

	if err := p.Close(5 * time.Second); err != nil {
		t.Fatalf("TEST-05 FAIL: shutdown wedge: %v", err)
	}

	sub, over, parsed, _, panics, emitted := p.Snapshot()
	if sub != int64(n) || over != 0 {
		t.Fatalf("submitted=%d overflow=%d, want %d/0", sub, over, n)
	}
	if parsed != sub {
		t.Fatalf("parsed=%d != submitted=%d — event loss", parsed, sub)
	}
	if panics != poison {
		t.Fatalf("panics=%d, want %d — poison isolation failed", panics, poison)
	}
	if emitted != seen.Load() { // every emission must match what the sink actually saw
		t.Fatalf("emitted=%d, want %d (as seen by sink)", emitted, seen.Load())
	}
	if seen.Load() != sub { // the sink sees every record before the panic
		t.Fatalf("seen by sink=%d want %d", seen.Load(), sub)
	}

	// Submit after Close: must return an error and must not block.
	done := make(chan error, 1)
	go func() { done <- p.Submit(frameWithPort(t, 1, []byte{0x16}, 443)) }()
	select {
	case err := <-done:
		if !errors.Is(err, ring.ErrClosed) {
			t.Fatalf("closed submit err=%v, want ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("TEST-05 FAIL: Submit blocked after Close")
	}
	// Double Close is idempotent.
	if err := p.Close(time.Second); err != nil {
		t.Fatalf("double close: %v", err)
	}
}

func frameWithPort(t *testing.T, cookie uint32, payload []byte, dport uint16) []byte {
	t.Helper()
	buf := make([]byte, abi.EventSize)
	e := &abi.Event{
		TimestampNS: 1, PidTgid: 2 << 16,
		Saddr: [4]byte{10, 0, 0, 1}, Daddr: [4]byte{10, 0, 0, 2},
		Sport: 1234, Dport: dport, Direction: abi.DirEgress,
		HSType: abi.HSClientHello, TLSVersion: 0x0303,
		Cookie: cookie, Payload: payload,
	}
	if err := e.Encode(buf); err != nil {
		t.Fatalf("encode: %v", err)
	}
	return buf
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
