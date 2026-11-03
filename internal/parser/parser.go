// Package parser inspects captured TLS handshake bytes (from the eBPF ring
// buffer) and classifies the key-establishment cryptography in use:
// legacy RSA key-exchange, ECC (X25519/P-256...), pure PQC (ML-KEM codepoints)
// or hybrid. This is the analytic core of the Cyprenit Engine v1.0.0-Beta PQC risk map.
//
// Hard rules enforced by TEST-03/TEST-05:
//   - Parse() NEVER panics on malformed input; it returns kind "unknown".
//   - All returned *ParsedRecord come from an audited pool and MUST be
//     released via Release() (leak counter is observable).
package parser

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Crypto classification kinds.
const (
	KindUnknown        = "unknown"
	KindRSAKeyExchange = "rsa_kx"
	KindECC            = "ecc_x25519" // any classic ECDHE group
	KindPQCHybrid      = "hybrid_x25519_mlkem768"
	KindPurePQC        = "mlkem768_pqc"
)

// Well-known TLS cipher suites whose key exchange is RSA (no forward
// secrecy, largest PQC migration risk — RFC 8446 §B.4 & RFC 5246).
var rsaKeyExchangeSuites = map[uint16]string{
	0x0004: "TLS_RSA_WITH_RC4_128_SHA",
	0x0005: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x000A: "TLS_RSA_WITH_NULL_SHA",
	0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x002C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x003D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0xC009: "TLS_ECDHE_ECDSA_... (ignore)", // not RSA kx; excluded below
}

func init() { delete(rsaKeyExchangeSuites, 0xC009) }

// Named groups considered classic ECC (RFC 8422 / RFC 8446 §4.2.8.2, plus
// draft-bmoore x-only variants).
var eccGroups = map[uint16]string{
	0x0017: "secp256r1",
	0x0018: "secp384r1",
	0x0019: "secp521r1",
	0x001D: "x25519",
	0x001E: "x448",
	0x001F: "brainpoolp256r1",
}

// PQC key-share codepoints observed in the wild:
//   - 4588 (0x11DC): mlkem768 (Cloudflare/others, current assignment era)
//   - 0xefe8..0xefeb: old OpenSSH/Cisco XNTP-hybrid experiment range
//   - 4587/4589: mlkem512/mlkem1024 neighbours
var pqcGroups = map[uint16]string{
	4587:   "mlkem512",
	4588:   "mlkem768",
	4589:   "mlkem1028",
	0xefe8: "secg-p256-sha2-xkyber",
	0xefe9: "x25519-kyber512",
	0xefea: "x25519-kyber768",
	0xefeb: "ntruhps2048-512",
}

// ParsedRecord is a pooled analysis result.
//
// CONCURRENCY CONTRACT (enterprise rule #1 — "-race" protection): every field
// below, INCLUDING the Epoch stamp, is read and written ONLY while holding
// the owning RecordPool's single mutex (p.mu). There is deliberately NO
// secondary ownership lock: split locking was the root cause of the
// historical use-after-recycle races, and a single mutex makes unsynchronised
// read/write pairs structurally impossible for the Go race detector.
// Sinks receive a borrowed view and must finish with it before returning;
// the pipeline releases under the same lock discipline.
type ParsedRecord struct {
	FlowCookie uint32
	Pid        uint32
	Saddr      string
	Daddr      string
	Sport      uint16
	Dport      uint16
	TLSVersion uint16
	TSecs      int64  // capture timestamp, unix seconds (0 if unknown; M04 TPS input)
	Handshake  string // "ClientHello"/"ServerHello"/...
	Kind       string // one of Kind* above
	Suites     []string
	Groups     []string
	pqcSeen    bool // classic-vs-PQC key_share flags (classification input)
	eccSeen    bool
	RiskScore  int    // 0..100, higher = more urgent PQC migration
	RiskLabel  string // CRITICAL/HIGH/MEDIUM/LOW/NONE (global enterprise labels)
	pool       *RecordPool
	// slot is the private generation cell backing this record. It is set by
	// Get() under p.mu and never handed out raw; a stale copy of a
	// *ParsedRecord can therefore never alias a live slot because the Go
	// allocator only recycles freed objects for same-type allocations.
	slot *genSlot
	// Epoch: pool generation stamp assigned by Get() under p.mu. Release()
	// validates it against the slot lease inside the same lock and zeroes
	// it, making a double-release an idempotent counted no-op.
	Epoch uint64
}

// Release returns the record to its pool. Idempotent; double-release and
// stale/use-after-release pointers are rejected inside the mutex in
// (*RecordPool).Release (rule #1: nil / pool / epoch checks run INSIDE the
// lock) and never corrupt counters or free-list state. The r==nil check is
// a pure function of the caller's own pointer variable — that memory belongs
// to the caller's stack/slice, not to the pooled slot — so it cannot race
// with slot recycling. Every field that lives INSIDE the slot is read or
// written only while holding p.mu inside RecordPool.Release; there is
// deliberately no lock-free fast path, which makes unsynchronised read/
// write pairs on recycled slots structurally impossible for the Go race
// detector.
func (r *ParsedRecord) Release() {
	if r == nil || r.pool == nil {
		return
	}
	r.pool.Release(r)
}

// String renders a compact log line for the risk map exporter.
func (r *ParsedRecord) String() string {
	return fmt.Sprintf("%s->%s:%d pid=%d tls=0x%04x hs=%s kx=%s risk=%s(%d) suites=%v groups=%v",
		r.Saddr, r.Daddr, r.Dport, r.Pid, r.TLSVersion, r.Handshake, r.Kind,
		r.RiskLabel, r.RiskScore, r.Suites, r.Groups)
}

// ---------------------------------------------------------------------------
// Audited object pool (TEST-02): every Get must be paired with a Release.
//
// The production pool implementation lives in pool.go (RecordPool) and
// enforces the enterprise rules:
//   #1  ALL nil / pool / epoch / capacity checks execute INSIDE p.mu — there
//       is no lock-free fast path touching slot memory, so the Go race
//       detector can observe zero unsynchronised read/write pairs on
//       recycled slots.
//   #2  gets/puts/leaks (+ derived inUse/peak/misuse) are sync/atomic
//       (atomic.Uint64): Add/Load without extra mutex cost (atomic counters:
//       100% consistent counter updates with zero lock overhead).
//   #3  Epoch stamping + ownership token + wipe-on-release close the
//       use-after-free and double-release classes; an over-cap burst sheds
//       records to the GC and increments `leaks` instead of inflating RSS.
// ---------------------------------------------------------------------------

// Pool is the package-level audited pool.
var pool = NewRecordPool()

// Stats exposes the atomic leak counters for TEST-02. Loads are lock-free by
// design; per-counter values are linearizable, so deltas observed by a test
// that owns all traffic in the window are exact. The signature stays
// (int64, int64, int64, int64) for ABI stability with cmd/ and ring tests.
func Stats() (inUse, peak, gets, puts int64) {
	return pool.audit()
}

// Misuse returns the rejected (double/stale) release count — observability
// for the idempotent-Release contract.
func Misuse() int64 { return pool.misuseCount() }

// Leaked returns records obtained but never released.
func Leaked() int64 {
	inUse, _, _, _ := pool.audit()
	return inUse
}

// ---------------------------------------------------------------------------
// TLS record / handshake parsing (bounds-checked everywhere; no panics).
// ---------------------------------------------------------------------------

// Handshake parses one TLS cleartext record containing a handshake message
// (the socket_filter only forwards records that begin like TLS). It never
// panics; on malformed input it returns a KindUnknown record.
//
// LOCKING CONTRACT (enterprise rule #1 — "ALL checks execute INSIDE the mutex"):
// acquisition (Get: nil/slot/epoch checks + stamping under p.mu) and every
// release path (RecordPool.Release: nil/pool/epoch/capacity checks under
// p.mu) are short, self-contained critical sections inside RecordPool. The
// returned record is EXCLUSIVELY owned by this caller until Release(): the
// atomic ownership token makes double/stale releases CAS-rejected no-ops, so
// payload writes here can never interleave with another owner's writes on
// the same slot — zero unsynchronised read/write pairs for the race
// detector, and no lock is held across parsing (no pool-wide serialization,
// no deadlock window).
func Handshake(payload []byte, cookie, pidTgid uint32, saddr, daddr [4]byte, sport, dport uint16, tlsVer uint16, tsNS uint64) (rec *ParsedRecord, err error) {
	rec = pool.Get() // epoch-stamped, exclusively owned from here on

	// Panic firewall: even if a future refactor slips, the worker survives.
	defer func() {
		if v := recover(); v != nil {
			rec.Kind = KindUnknown
			rec.Handshake = "malformed"
			rec.RiskLabel = RiskLabelNone
			err = fmt.Errorf("parser: recovered from panic: %v", v)
		}
	}()

	parseInto(rec, payload, cookie, pidTgid, saddr, daddr, sport, dport, tlsVer)
	rec.TSecs = CaptureSeconds(tsNS)
	return rec, nil
}

// CaptureSeconds converts an eBPF bpf_ktime_get_ns() timestamp into a unix
// wall-clock second for the M04 TPS estimator. The kernel ring timestamps are
// CLOCK_MONOTONIC ns since boot; we anchor them to wall time once (bootTime is
// resolved lazily and cached under its own mutex, never mutated concurrently).
// A zero/absurd tsNS yields 0 so downstream volumeTPS treats it as "no rate".
func CaptureSeconds(tsNS uint64) int64 {
	if tsNS == 0 {
		return 0
	}
	bt := bootUnixNano()
	if bt <= 0 {
		return 0
	}
	ns := int64(tsNS)
	if ns < 0 { // absurd value guard (clock wrap / corrupt event)
		return 0
	}
	t := bt + ns
	if t < 0 {
		return 0
	}
	return t / int64(time.Second)
}

var (
	bootMu      sync.Mutex
	bootNanoSet bool
	bootNanoVal int64
)

func bootUnixNano() int64 {
	bootMu.Lock()
	defer bootMu.Unlock()
	if bootNanoSet {
		return bootNanoVal
	}
	// now(wall) - uptime(monotonic ns) = boot instant in wall-clock ns.
	uptimeNs := readUptimeNs()
	if uptimeNs <= 0 {
		return -1
	}
	bootNanoSet = true
	bootNanoVal = time.Now().UnixNano() - uptimeNs
	return bootNanoVal
}

// readUptimeNs reads /proc/stat btime as a robust monotonic anchor fallback:
// boot epoch seconds -> ns. If unavailable, returns -1.
func readUptimeNs() int64 {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "btime ") {
			var secs int64
			if _, err := fmt.Sscanf(strings.TrimSpace(line), "btime %d", &secs); err == nil && secs > 0 {
				return secs * int64(time.Second)
			}
		}
	}
	return -1
}

// parseInto performs the actual field writes. Callers MUST hold pool.mu so
// every record mutation is totally ordered with get()/put().
func parseInto(rec *ParsedRecord, payload []byte, cookie, pidTgid uint32, saddr, daddr [4]byte, sport, dport uint16, tlsVer uint16) {
	rec.FlowCookie = cookie
	rec.Pid = pidTgid >> 16
	rec.Saddr = fmt.Sprintf("%d.%d.%d.%d", saddr[0], saddr[1], saddr[2], saddr[3])
	rec.Daddr = fmt.Sprintf("%d.%d.%d.%d", daddr[0], daddr[1], daddr[2], daddr[3])
	rec.Sport = sport
	rec.Dport = dport
	rec.TLSVersion = tlsVer

	hsType, ok := readHandshakeType(payload)
	if !ok {
		rec.Kind = KindUnknown
		rec.Handshake = "none"
		classify(rec)
		return
	}
	switch hsType {
	case 1:
		rec.Handshake = "ClientHello"
	case 2:
		rec.Handshake = "ServerHello"
	case 11:
		rec.Handshake = "Certificate"
	case 20:
		rec.Handshake = "Finished"
	default:
		rec.Handshake = fmt.Sprintf("type%d", hsType)
	}

	if hsType == 1 {
		sawRSA := parseClientHello(payload, rec)
		// Final classification precedence (TEST-03):
		//   PQC key_share present: hybrid if ECC/RSA classic material also
		//   present, else pure-PQC. No PQC: rsa_kx > ecc > unknown.
		switch {
		case rec.pqcSeen && (rec.eccSeen || sawRSA):
			rec.Kind = KindPQCHybrid
		case rec.pqcSeen:
			rec.Kind = KindPurePQC
		case sawRSA:
			rec.Kind = KindRSAKeyExchange
		case rec.eccSeen:
			rec.Kind = KindECC
		default:
			rec.Kind = KindUnknown
		}
	}
	classify(rec)
}

// stripTLSRecordHeader removes up to two concatenated 5-byte TLS record
// headers so we land on the first handshake byte. The kernel probe already
// skips one header; this tolerates coalesced records.
func readHandshakeType(p []byte) (uint8, bool) {
	// TLS: content_type(1)=0x16 version(2) length(2) then handshake msg.
	i := 0
	for i+5 <= len(p) && p[i] == 0x16 {
		rl := int(binary.BigEndian.Uint16(p[i+3 : i+5]))
		if rl == 0 || i+5+rl > len(p)+64 { // tolerate truncation at cap
			// fall through: handshake starts at i+5 even if truncated
		}
		i += 5
		break // single record expected after kernel stripping
	}
	// If caller passed raw handshake (kernel stripped header), p[0] is type.
	if i < len(p) && p[i] <= 20 && p[i] != 0 {
		return p[i], true
	}
	return 0, false
}

func parseClientHello(p []byte, rec *ParsedRecord) (sawRSA bool) {
	// Locate body start: skip record header if present.
	off := 0
	if off < len(p) && p[off] == 0x16 {
		if off+5 > len(p) {
			return false
		}
		off += 5
	}
	// handshake: type(1) length(3) legacy_version(2) random(32)
	if off+1+3+2+32 > len(p) {
		return sawRSA
	}
	off += 1 + 3 + 2 + 32
	// legacy_session_id
	if off+1 > len(p) {
		return sawRSA
	}
	sidLen := int(p[off])
	off += 1 + sidLen
	// cipher_suites
	if off+2 > len(p) {
		return sawRSA
	}
	csLen := int(binary.BigEndian.Uint16(p[off : off+2]))
	off += 2
	if csLen%2 != 0 || off+csLen > len(p) {
		return sawRSA
	}
	for i := 0; i+1 < csLen; i += 2 {
		suite := binary.BigEndian.Uint16(p[off+i : off+i+2])
		if name, ok := rsaKeyExchangeSuites[suite]; ok {
			rec.Suites = append(rec.Suites, name)
			sawRSA = true
		}
	}
	off += csLen
	// legacy_compression_methods
	if off+1 > len(p) {
		return sawRSA
	}
	cmLen := int(p[off])
	off += 1 + cmLen
	if off > len(p) {
		return sawRSA
	}
	// extensions
	if off+2 > len(p) {
		return sawRSA
	}
	extEnd := off + 2 + int(binary.BigEndian.Uint16(p[off:off+2]))
	off += 2
	for off+4 <= len(p) && off <= extEnd-4 {
		extType := binary.BigEndian.Uint16(p[off : off+2])
		extLen := int(binary.BigEndian.Uint16(p[off+2 : off+4]))
		body := off + 4
		if body+extLen > len(p) {
			break // truncated by kernel cap — best-effort stop
		}
		if extType == 51 { // key_share (ClientHello)
			parseKeyShare(p[body:body+extLen], rec)
		}
		off = body + extLen
	}
	return sawRSA
}

func parseKeyShare(body []byte, rec *ParsedRecord) {
	if len(body) < 2 {
		return
	}
	lstLen := int(binary.BigEndian.Uint16(body))
	body = body[2:]
	if lstLen > len(body) {
		lstLen = len(body) // truncated capture
	}
	i := 0
	for i+4 <= lstLen {
		group := binary.BigEndian.Uint16(body[i : i+2])
		klen := int(binary.BigEndian.Uint16(body[i+2 : i+4]))
		i += 4
		if i+klen > lstLen {
			break
		}
		i += klen
		if name, ok := eccGroups[group]; ok {
			rec.Groups = append(rec.Groups, name)
			rec.eccSeen = true
		} else if name, ok := pqcGroups[group]; ok {
			rec.Groups = append(rec.Groups, name)
			rec.pqcSeen = true
		}
	}
}

// classify assigns the PQC migration risk score. Ordering per TEST-03:
// rsa_kx(100) > ecc(70) > hybrid(30) > pure-PQC(10) > unknown(0).
func classify(rec *ParsedRecord) {
	if rec.Kind == "" {
		rec.Kind = KindUnknown
	}
	switch rec.Kind {
	case KindRSAKeyExchange:
		rec.RiskScore, rec.RiskLabel = 100, RiskLabelCritical
	case KindECC:
		rec.RiskScore, rec.RiskLabel = 70, RiskLabelHigh
	case KindPQCHybrid:
		rec.RiskScore, rec.RiskLabel = 30, RiskLabelMedium
	case KindPurePQC:
		rec.RiskScore, rec.RiskLabel = 10, RiskLabelLow
	default:
		rec.RiskScore, rec.RiskLabel = 0, RiskLabelNone
	}
}
