# Cyprenit Engine

**Version:** v1.0.0-Beta
**License:** GPL-3.0-only
**Language:** Go 1.19+ (user-space), C (eBPF kernel-space)

Cyprenit Engine is a **passive, non-invasive eBPF telemetry agent** that builds a
Post-Quantum-Cryptography (PQC) risk map of TLS traffic on Linux servers — without
touching, delaying or terminating any packet. It is a fully sector-neutral,
independent **Cyber Resilience & PQC Infrastructure** tool built for Linux
data centers where inline middleboxes are prohibited and audit evidence must
be reproducible byte-for-byte.

---

## Why "non-invasive"?

Cyprenit attaches a `BPF_PROG_TYPE_SOCKET_FILTER` program to observation sockets.
A socket filter runs in the packet path but:

- **Never modifies packets.** The kernel program only *reserves* space in an eBPF
  **ring buffer** and copies up to 92 bytes of a detected TLS handshake record.
- **Never blocks.** `bpf_ringbuf_reserve()` fails open: under memory pressure the
  event is dropped in kernel space with a counter bump (`drops`), instead of
  stalling the datapath. Throughput impact is measured in nanoseconds per packet.
- **Zero-copy async delivery.** User-space consumes events from the ring buffer
  through a lock-light fan-out pipeline; slow analysis never backpressures the
  kernel producer.

## Architecture

```
┌─────────────────────── Linux Kernel ────────────────────────┐
│  socket_filter (ebpf/tls_probe.bpf.c)                       │
│   • detects TLS record header (content_type == 0x16)        │
│   • parses ClientHello cipher-suite list                    │
│   • struct cyprenit_evt (fixed 128 B ABI) → ring buffer     │
└──────────────────────────┬──────────────────────────────────┘
                           │ bpf_ring_buffer (async, lock-free)
┌──────────────────────────▼──────────────────────────────────┐
│  User-space daemon (cmd/cyprenit)                            │
│   internal/ring    : drain-then-close async pipeline         │
│                      (4-worker fan-out, panic firewall)      │
│   internal/parser  : TLS classification + RecordPool         │
│                      (mutex-guarded epoch checks,            │
│                       atomic.Uint64 gets/puts/leaks counters)│
│   internal/metrics : PQC risk map + audit-grade reporting    │
│                      (DORA Art. 9 & 12, ISO/IEC             │
│                       27001:2022 A.8.24)                     │
└──────────────────────────────────────────────────────────────┘
```

### Risk scoring

| Detected key exchange / suite                     | Class       | RiskScore | Priority                  |
|---------------------------------------------------|-------------|-----------|---------------------------|
| Static RSA key exchange (e.g. `TLS_RSA_*`)        | RSA         | **100**   | CRITICAL/IMMEDIATE ACTION |
| ECDHE over classical curves (P-256, X25519)       | ECC         | **70**    | HIGH RISK                 |
| Hybrid PQC (e.g. ML-KEM/X25519 codepoints)        | HYBRID_PQC  | **30**    | MEDIUM RISK               |
| Pure PQC                                          | PURE_PQC    | **10**    | LOW RISK                  |
| Malformed / unparseable handshake                 | UNKNOWN     | 0         | İnformational             |

M04 (Business Impact Translation) converts each server flow's `VolumeTPS` into
a per-minute USD projection of infrastructure outage and reputation-loss cost
(CRITICAL: ×450, HIGH: ×150 coefficient) and the report carries a **TOTAL
INFRASTRUCTURE FINANCIAL RISK PROJECTION** total. When any CRITICAL finding
exists, the report auto-appends **APPENDIX-A: DRAFT GLOBAL MATERIAL-INCIDENT
AND COMPLIANCE NOTIFICATION FORM**, including the 72-hour HNDL notification
clock.

---

## Critical unit test plan (TEST-01 … TEST-05)

The concurrency contract was written *before* implementation code:

| ID      | Scenario | What it pins down |
|---------|----------|-------------------|
| TEST-01 | **Deadlock** — saturated pool + slow sink; `Submit()` must never block beyond budget and `Close()` must complete gracefully. | Pipeline liveness, no wedge, no goroutine leak. |
| TEST-02 | **Leak** — full get/release cycles under `-race`; `gets == puts`, `inUse == 0`, over-cap bursts shed to GC and bump `leaks` (never RSS). | Pool accounting exactness, double-release rejection. |
| TEST-03 | **Boundary / misclassification** — golden handshakes for RSA / ECC / pure-PQC / hybrid / malformed must map to exactly their class & score. | Analytic correctness of the risk map at protocol boundaries. |
| TEST-04 | **ABI regression** — golden hex vector of `struct cyprenit_evt` (128 B) round-trips byte-for-byte between kernel layout and Go decoder. | Kernel↔user contract stability (`BPF_MAP_TYPE_RINGBUF` payload layout). |
| TEST-05 | **Shutdown** — 1000 concurrent events with panicking consumer callbacks; panic firewall counts them, drain-then-close flushes everything, `overflow == 0`. | Async delivery under fault injection, graceful teardown. |

Run them (all pass under the Go race detector):

```bash
go build ./... && go vet ./...
go test -race -count=1 ./...
```

---

## Getting started

### Requirements (live eBPF mode)

- Linux ≥ 5.8 with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`)
- Root or `CAP_BPF` + `CAP_PERFMON`
- Build toolchain: `sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) bpftool golang-go`

### Build

```bash
git clone https://github.com/SteppL10n-prog/cyprenit.git
cd cyprenit
go build -o bin/cyprenit ./cmd/cyprenit
```

### Three operating modes

**1. Dry-run (no root, no NIC)** — synthetic telemetry through the full pipeline:

```bash
./bin/cyprenit -dry-run -duration 8s -report 2s -out audit.md
```

**2. Pcap replay** — analyse captured traffic offline (also no root required):

```bash
sudo tcpdump -i eth0 -w capture.pcap 'tcp port 443'   # collect
./bin/cyprenit -pcap capture.pcap -report 5s -out audit.md
```

**3. Live eBPF** — passive kernel-side observation:

```bash
sudo ./bin/cyprenit -ifindex 0 -report 10s -out /var/log/cyprenit_audit.md
```

Optional pre-filters (reduce noise and cost in all live/pcap paths):

```bash
sudo ./bin/cyprenit -capture-nets 10.0.4.0/24,172.16.0.0/16 \
                    -capture-ports 443,8443 -report 10s -out audit.md
```

### Output

Each run writes a deterministic Markdown audit report containing:

- per-flow table (network, port, algorithm class, risk score, TPS, USD/min projection),
- max-risk classification and total infrastructure risk projection (M04),
- standard references: DORA Art. 9 & 12 · ISO/IEC 27001:2022 A.8.24,
- conditional EK-A global material-incident & compliance draft notification (M03).

Quick triage helpers:

```bash
grep -n "CRITICAL" audit.md          # urgent flows
grep -n "Hybrid\|PURE_PQC" audit.md  # PQC-ready inventory
```

---

## Repository layout

```
cmd/cyprenit/          user-space loader & daemon (cilium/ebpf)
ebpf/tls_probe.bpf.c   kernel-side socket_filter + ring buffer producer
internal/abi/          fixed 128-byte struct cyprenit_evt contract
internal/ring/         async drain-then-close pipeline (TEST-01/05)
internal/parser/       TLS classifier + thread-safe RecordPool (TEST-02/03)
internal/metrics/      risk map + Cyprenit-standard report engine (M03/M04)
docs/                  test plan & operator guide
LICENSE                GPL-3.0
```

## Compliance notes

Cyprenit produces *proactive risk-reduction findings*, not incident proof. The
EK-A appendix is a **draft** and is explicitly marked as requiring legal &
compliance sign-off before submission to any authority.

## License

Cyprenit Engine is released under the **GNU General Public License v3.0**
(SPDX: `GPL-3.0-only`). See [LICENSE](LICENSE).
