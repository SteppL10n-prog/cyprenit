package ring

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/SteppL10n-prog/cyprenit/internal/abi"
	"github.com/SteppL10n-prog/cyprenit/internal/parser"
	"github.com/SteppL10n-prog/cyprenit/internal/testdata"
)

func TestZZTraceWedge(t *testing.T) {
	p := NewPipeline(8, 1024, func(rec *parser.ParsedRecord) {

		if rec.Dport == 9999 {
			panic("poison")
		}
	})
	for i := 0; i < 1000; i++ {
		dport := uint16(443)
		payload := testdata.ECCClientHello[5:]
		if i < 20 {
			dport = 9999
			payload = testdata.RSAClientHello[5:]
		}
		buf := make([]byte, abi.EventSize)
		pl := payload
		if len(pl) > abi.PayloadMax {
			pl = pl[:abi.PayloadMax]
		}
		e := &abi.Event{TimestampNS: 1, PidTgid: 2 << 16, Saddr: [4]byte{10, 0, 0, 1}, Daddr: [4]byte{10, 0, 0, 2},
			Sport: 1234, Dport: dport, Direction: abi.DirEgress, HSType: abi.HSClientHello, TLSVersion: 0x0303,
			Cookie: uint32(i), Payload: pl}
		_ = e.Encode(buf)
		if err := p.Submit(buf); err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
	}
	err := <-pCloseDone(p)
	t.Logf("close err: %v", err)
	time.Sleep(300 * time.Millisecond)
	sub, over, parsed, _, panics, emitted := p.Snapshot()
	inUse, peak, gets, puts := parser.Stats()
	t.Logf("sub=%d over=%d parsed=%d panics=%d emitted=%d | pool inUse=%d peak=%d gets=%d puts=%d",
		sub, over, parsed, panics, emitted, inUse, peak, gets, puts)
	b := make([]byte, 1<<20)
	n := runtime.Stack(b, true)
	for _, blk := range strings.Split(string(b[:n]), "\ngoroutine ") {
		if strings.Contains(blk, "katman4/internal/ring.(*Pipeline)") {
			lines := strings.SplitN(blk, "\n", 8)
			t.Logf("ALIVE-GOROUTINE:\ngoroutine %s", strings.Join(lines, "\n"))
		}
	}
}

func pCloseDone(p *Pipeline) chan error {
	ch := make(chan error, 1)
	go func() { ch <- p.Close(5 * time.Second) }()
	return ch
}
