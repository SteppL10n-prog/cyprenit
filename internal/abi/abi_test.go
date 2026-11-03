// TEST-04 — Kernel/User Wire Format Compliance (ABI): Go encode/decode ↔ fixed C struct cyprenit_evt
// C struct cyprenit_evt. The golden hex vector breaks ABI regressions in CI.
package abi_test

import (
	"encoding/hex"
	"testing"

	"github.com/SteppL10n-prog/cyprenit/internal/abi"
)

// tailZeros = EventSize-36-4 payload bytes zero-filled, as a compile-time
// constant string (must equal 88 bytes => 176 '0' chars).
const tailZeros = "000000000000000000000000000000000000000000000000000000000000000000000000" +
	"000000000000000000000000000000000000000000000000000000000000000000000000" +
	"00000000000000000000000000000000"

func sample() *abi.Event {
	return &abi.Event{
		TimestampNS: 0x0102030405060708,
		PidTgid:     0xAABBCCDD,
		Saddr:       [4]byte{192, 0, 2, 1},
		Daddr:       [4]byte{10, 0, 4, 250},
		Sport:       0x1234,
		Dport:       0x01BB, // 443
		Direction:   abi.DirEgress,
		HSType:      abi.HSClientHello,
		TLSVersion:  0x0303,
		RecordLen:   4,
		Cookie:      0xFEEDFACE,
		Payload:     []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
}

// golden is the exact byte layout of struct cyprenit_evt for sample().
// If anyone changes field order/size on either side, this fails FIRST.
var golden = "" +
	"0102030405060708" + // timestamp_ns
	"aabbccdd" + // pid_tgid
	"c0000201" + // saddr
	"0a0004fa" + // daddr
	"1234" + // sport
	"01bb" + // dport
	"00" + // direction
	"01" + // hs_type
	"0303" + // tls_version
	"0004" + // record_len
	"0000" + // pad0
	"feedface" + // cookie
	"deadbeef" + // payload[0..3]
	tailZeros // zero-filled tail (88 bytes)

func TestTEST04_GoldenWireVector(t *testing.T) {
	want, err := hex.DecodeString(golden)
	if err != nil {
		t.Fatalf("golden hex bozuk: %v", err)
	}
	if len(want) != abi.EventSize {
		t.Fatalf("golden length %d != EventSize %d", len(want), abi.EventSize)
	}
	buf := make([]byte, abi.EventSize)
	if err := sample().Encode(buf); err != nil {
		t.Fatalf("encode: %v", err)
	}
	got := hex.EncodeToString(buf)
	if got != hex.EncodeToString(want) {
		t.Fatalf("ABI REGRESYONU!\n got=%s\nwant=%s", got, hex.EncodeToString(want))
	}
}

func TestTEST04_RoundTrip(t *testing.T) {
	buf := make([]byte, abi.EventSize)
	e := sample()
	if err := e.Encode(buf); err != nil {
		t.Fatal(err)
	}
	d, err := abi.Decode(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if d.TimestampNS != e.TimestampNS || d.PidTgid != e.PidTgid ||
		d.Sport != e.Sport || d.Dport != e.Dport ||
		d.Direction != e.Direction || d.HSType != e.HSType ||
		d.TLSVersion != e.TLSVersion || d.RecordLen != e.RecordLen ||
		d.Cookie != e.Cookie || string(d.Payload) != string(e.Payload) {
		t.Fatalf("round-trip mismatch: %+v vs %+v", d, e)
	}
	if d.Saddr != e.Saddr || d.Daddr != e.Daddr {
		t.Fatalf("address round-trip mismatch")
	}
}

func TestTEST04_RejectsBadFramesNoPanic(t *testing.T) {
	if _, err := abi.Decode(make([]byte, abi.EventSize-1)); err == nil {
		t.Fatal("short buffer must return an error")
	}
	// RecordLen > PayloadMax => decode error (the kernel never produces this;
	// malformed/cast-corrupted data protection).
	buf := make([]byte, abi.EventSize)
	sample().Encode(buf)
	buf[28], buf[29] = 0xFF, 0xFF
	if _, err := abi.Decode(buf); err == nil {
		t.Fatal("overflowing record_len must be rejected")
	}
	// Encode with an undersized buffer => error, no panic.
	if err := (&abi.Event{}).Encode(make([]byte, 10)); err == nil {
		t.Fatal("expected Encode error for undersized buffer")
	}
}
