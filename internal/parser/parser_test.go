// TEST-03 — TLS Handshake Parser: RSA / ECC / ML-KEM / Hybrid PQC
// NO panic on malformed input. Real RFC 8446 wire-format vectors.
package parser_test

import (
	"bytes"
	"testing"

	"github.com/SteppL10n-prog/cyprenit/internal/parser"
	"github.com/SteppL10n-prog/cyprenit/internal/testdata"
)

func parse(t *testing.T, hello []byte) *parser.ParsedRecord {
	t.Helper()
	// The kernel probe strips the 5-byte TLS record header; payload is the handshake.
	rec, err := parser.Handshake(hello[5:], 0xfeed, 42<<16,
		[4]byte{10, 0, 0, 5}, [4]byte{10, 0, 4, 250}, 41234, 443, 0x0303, 0)
	if err != nil {
		t.Fatalf("Handshake hata: %v", err)
	}
	t.Cleanup(rec.Release)
	return rec
}

func TestTEST03_DetectsRSAKeyExchange(t *testing.T) {
	rec := parse(t, testdata.RSAClientHello)
	if rec.Kind != parser.KindRSAKeyExchange {
		t.Fatalf("kind=%s, want %s", rec.Kind, parser.KindRSAKeyExchange)
	}
	if rec.RiskScore != 100 || rec.RiskLabel != "CRITICAL" {
		t.Fatalf("risk=%d/%s, want 100/CRITICAL", rec.RiskScore, rec.RiskLabel)
	}
	if !bytes.Contains([]byte(rec.String()), []byte("TLS_RSA_WITH_AES_128_GCM_SHA256")) {
		t.Fatalf("cipher suite list not found: %v", rec.Suites)
	}
}

func TestTEST03_DetectsECCX25519(t *testing.T) {
	rec := parse(t, testdata.ECCClientHello)
	if rec.Kind != parser.KindECC {
		t.Fatalf("kind=%s, want %s", rec.Kind, parser.KindECC)
	}
	if rec.RiskScore != 70 || rec.RiskLabel != "HIGH" {
		t.Fatalf("risk=%d/%s, want 70/HIGH", rec.RiskScore, rec.RiskLabel)
	}
	if len(rec.Groups) == 0 || rec.Groups[0] != "x25519" {
		t.Fatalf("groups=%v, want x25519", rec.Groups)
	}
}

func TestTEST03_DetectsPurePQCMLKem768(t *testing.T) {
	rec := parse(t, testdata.PQCClientHello)
	if rec.Kind != parser.KindPurePQC {
		t.Fatalf("kind=%s, want %s", rec.Kind, parser.KindPurePQC)
	}
	if rec.RiskScore != 10 {
		t.Fatalf("risk=%d, want 10", rec.RiskScore)
	}
}

func TestTEST03_DetectsHybridX25519MLKem(t *testing.T) {
	rec := parse(t, testdata.HybridClientHello)
	if rec.Kind != parser.KindPQCHybrid {
		t.Fatalf("kind=%s, want %s", rec.Kind, parser.KindPQCHybrid)
	}
	if rec.RiskScore != 30 {
		t.Fatalf("risk=%d, want 30", rec.RiskScore)
	}
}

// Fuzz-lite: truncations and byte corruption must NEVER panic and must
// degrade to a released-safe record (unknown or best-effort classification).
func TestTEST03_MalformedInputNeverPanics(t *testing.T) {
	base := testdata.HybridClientHello
	for cut := 0; cut < len(base); cut++ {
		rec, _ := parser.Handshake(base[:cut], 1, 1,
			[4]byte{1, 1, 1, 1}, [4]byte{2, 2, 2, 2}, 1, 2, 0x0303, 0)
		if rec == nil {
			t.Fatalf("nil record for cut=%d", cut)
		}
		rec.Release()
	}
	// corrupted lengths everywhere
	corrupt := append([]byte(nil), base...)
	for i := range corrupt {
		corrupt[i] ^= 0xFF
		if i > 40 {
			break
		}
	}
	rec, _ := parser.Handshake(corrupt, 1, 1,
		[4]byte{1, 1, 1, 1}, [4]byte{2, 2, 2, 2}, 1, 2, 0x0303, 0)
	if rec == nil {
		t.Fatal("nil record on corruption")
	}
	if rec.Kind != parser.KindUnknown && rec.Kind != parser.KindRSAKeyExchange &&
		rec.Kind != parser.KindECC && rec.Kind != parser.KindPQCHybrid && rec.Kind != parser.KindPurePQC {
		t.Fatalf("invalid kind: %s", rec.Kind)
	}
	rec.Release()
	// empty + random garbage
	for _, junk := range [][]byte{{}, {0x16}, {0x16, 0x03}, bytes.Repeat([]byte{0xAA}, 92)} {
		r, _ := parser.Handshake(junk, 0, 0, [4]byte{}, [4]byte{}, 0, 0, 0, 0)
		if r != nil {
			r.Release()
		}
	}
}
