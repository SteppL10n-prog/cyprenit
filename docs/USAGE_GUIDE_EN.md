# Cyprenit Engine v1.0.0-Beta — Kali Linux Usage Guide (Step by Step)

**Layer 4: Async eBPF Passive Discovery Prototype — PQC Risk Map**

This guide walks you step by step through installing and running the
`cyprenit-async` tool in a Kali Linux terminal, understanding what it inspects
and where, and producing a Cyprenit compliance (DORA/ISO 27001) audit report.

## 0. Architecture Overview — "What Does It Inspect, Where?"

```
[Network Packet]                                                 [Report]
     |                                                              ^
     v                                                              |
eBPF socket_filter (observe-only, always TC_ACT_OK) -----> ring buffer ----> async Go pipeline ----> risk map ----> Markdown audit.md
     |                        |                              |
     v                        v                              v
 kernel datapath        drop counter on overflow      internal/parser/pool.go : RecordPool (mutex-guarded epoch + atomic counters)
 (untouched)                                            internal/parser/parser.go : cipher-suite classification (RSA/ECC/Hybrid/PurePQC)
                                                        internal/metrics/riskmap.go : per-flow risk map (score 0-100)
                                                        internal/abi : pinned 128-byte kernel<->user ABI contract
```

**What is inspected:** the **cipher suite list** and the **supported_groups /
key_share** extensions inside TLS handshake packets on TCP port 443 (extended
via `-ports`). From these the server's cryptographic posture is derived:

| Key exchange observed | Meaning | RiskScore |
|---|---|---|
| Static RSA (`TLS_RSA_*`) | HNDL-exposed, immediate migration required | 100 = CRITICAL |
| ECDHE (X25519/P-256) | ECC, vulnerable to harvest-now-decrypt-later | 70 = HIGH |
| ML-KEM / X25519MLKEM768 hybrid | Migration in progress | 30 = MEDIUM |
| Pure PQC suite (ML-KEM only) | Post-quantum ready | 0 = LOW |

**Non-invasive principle:** packets are never touched, connections are never
interrupted — observation only. If the ring buffer fills, events drop but the
application is never blocked (the drop counter is reflected in the report).

## 1. Preparation — System Requirements (Kali)

For live eBPF mode:

```bash
uname -r          # Kernel >= 5.18 recommended (Kali rolling already qualifies)
sudo -v           # Root privileges required (to load eBPF programs)
```

Toolchain installation:

```bash
sudo apt install -y clang llvm libbpf-dev tcpdump golang-go
go version        # must be >= 1.21
```

> **Note:** the `ebpf/tls_probe.bpf.o` shipped with the repo may not have been
> built against the target machine's headers; we will recompile it on Kali in
> Section 2.

## 2. Transferring / Building the Project on Kali

After obtaining the project via ZIP/Git on Kali:

```bash
cd cyprenit
# Go user space — build + tests (no eBPF required; runs in any environment)
go build ./...
go vet ./...
go test -race -count=1 ./...        # TEST-01..05 must all PASS
go build -o bin/cyprenit-async ./cmd/cyprenit-async
./bin/cyprenit-async -h             # show flags
```

### (Optional) Rebuilding the eBPF object on Kali

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
      -I/usr/include -c ebpf/tls_probe.bpf.c -o ebpf/tls_probe.bpf.o
```

## 3. Run Modes

The tool has three run modes. The first two do NOT require root/kernel eBPF —
start your trial there.

### MODE A — `-dry-run` (synthetic telemetry, end-to-end trial without eBPF)

Purpose: exercise the pipeline, pool, classifier and report engine without a
live network.

```bash
./bin/cyprenit-async -dry-run -duration 30s -out /tmp/audit-dry.md
# Watch the output
```

Success criteria (look for them in the terminal output):
- `pool in-use=0` → no memory leak (TEST-02 behaviour holds live too)
- `drops=0` or low → no backpressure
- a line like `shutdown clean` at exit → no deadlock (TEST-01/05)

### MODE B — `-pcap` (replay recorded traffic — real detection trial)

The safest way to validate the classifier against genuine TLS handshakes.

```bash
# 1) Capture a pcap from your target (or generate one in your own lab):
#    The command below produces SAMPLE TLS traffic belonging ONLY to your own network:
sudo tcpdump -i lo -w /tmp/lab.pcap port 443 &
# Trigger a few real TLS sessions:
curl -s https://localhost >/dev/null || true
openssl s_client -connect example.internal:443 </dev/null >/dev/null 2>&1 || true
sudo kill %1

# 2) Replay through the full pipeline:
./bin/cyprenit-async -pcap /tmp/lab.pcap -out /tmp/audit-pcap.md
```

Validation: the suites listed by `grep Cipher` (e.g. `TLS_AES_256_GCM_SHA384`,
`TLS_CHACHA20_POLY1305_SHA256`) must be mapped to the **correct risk class** in
the report table (ECDHE+AES-GCM → ECC class, HIGH RISK; RSA-kex → CRITICAL).

### MODE C — Live eBPF passive discovery (the primary use case)

Corporate data-center scenario: listen to the server's network traffic
**without interrupting it**.

```bash
# 1) Find the ifindex of the interface to observe:
ip link                # e.g. 2: eth0: <...>  => ifindex = 2

# 2) Start (for all interfaces use -ifindex 0):
sudo ./bin/cyprenit-async -ifindex 2 -report 5s -out /var/log/cyprenit_audit.md

# 3) From another terminal, provoke some traffic (for testing):
curl -sv https://target.internal >/dev/null 2>&1

# 4) Stop after the duration or with Ctrl-C; check the shutdown logs:
#    pool in-use=0, drops stable, no goroutine leak
```

Graceful shutdown via signal (SIGTERM = graceful shutdown, drain-then-close):

```bash
sudo pkill -TERM cyprenit-async
```

## 4. What, Where, How to Inspect? (Operational Checklist)

Review the following in order during an audit:

1. **Identity/permissions:** is the file given to `-out` on the
   `sudo ./bin/cyprenit-async ...` command line actually written?
   (`ls -la /var/log/cyprenit_audit.md`)
2. **Inventory:** report table rows == detected flows.
3. **Critical exposure triage:**
   ```bash
   grep -E "CRITICAL|IMMEDIATE" ~/cyprenit-out/*.md
   ```
   → servers using RSA key exchange = priority #1 in the migration plan.
4. **Hybrid/migration tracking:**
   ```bash
   grep -E "HYBRID|MEDIUM" ~/cyprenit-out/*.md
   ```
   → systems already on ML-KEM hybrids but not yet pure PQC (follow-up item for DORA Art. 12).
5. **Data integrity:** the `drops` and `overflow` counters in the terminal log.
   High drop rate → raise `-queue-depth 8192` or set `-workers 8`.
6. **Leak audit:** the `pool in-use` value at every shutdown. Non-zero means
   records escaped → reproduce with `go test -race -run TestLeakDetector ./internal/...`.
7. **Permission errors:** `Operation not permitted` → you are not root, or
   kernel lockdown/BPF restrictions apply:
   ```bash
   sudo sysctl kernel.unprivileged_bpf_disabled=0   # temporary; revert after the audit
   ```
8. **Wrong interface:** if no flows appear, confirm the correct `-ifindex` was
   given via `ip addr`; on VLAN/bonding, observe the physical parent.

## 5. Report Output — How to View and Share It?

The Markdown produced with `-out` has 3 sections aligned to audit standards:

- **Header summary:** MaxRisk field (CRITICAL / IMMEDIATE ACTION REQUIRED, HIGH RISK, MEDIUM RISK, LOW RISK, NONE)
- **Flow table:** the columns above
- **Standards reference block:** DORA Art. 9 & 12, ISO/IEC 27001:2022 A.8.24

Reading/distribution:

```bash
glow ~/cyprenit-out/audit-pcap.md            # colour view in the terminal (apt install glow)
pandoc ~/cyprenit-out/audit.md -o audit.pdf  # convert to PDF, send to management
```

## 6. Frequently Encountered Issues (Troubleshooting)

| Symptom | Cause | Fix |
|---|---|---|
| `failed to load BPF object` | `.o` not built for the target kernel | Recompile on Kali via the `clang` step in Section 2 |
| `RTNETLINK answers: Operation not supported` | TC/socket attach restriction | Root + specific `-ifindex` interface |
| Empty report (`NONE`) | No TLS on the observed path / wrong ifindex | Verify traffic with `ip link`, `tcpdump -i any port 443` |
| `drops` rising | Queue saturation | `-queue-depth 16384 -workers 8` |
| Shutdown hangs | (fixed in v1.0.0-Beta: drain-then-close) | If it recurs: `sudo pkill -INT` + issue report |
| `-race` test FAIL (developer) | ABI/counter regression | Reproduce with `go test -race -count=5 ./internal/...` |

## 7. Safe Termination / Shutdown Protocol (End of Audit)

```bash
# 1) Was the process shut down cleanly?
pgrep -fa cyprenit-async || echo "closed"

# 2) Any leftover BPF programs/maps?
sudo bpftool prog list | grep socket || echo "no residual programs"
sudo bpftool map list | grep tls_events || echo "no residual maps"

# 3) Raw-data policy: move pcap and audit files into an encrypted archive
```

## 7b. Verified Sample Output (generated together with this repo's `-race` tests)

Real `-dry-run` output — expect the same values in your own run:

```
== Cyprenit PQC Risk Map == submitted=2 overflow=0 parsed=2 emitted=2 panics=0
shutdown: pool in-use=0 peak=1 gets=2 puts=2 (in-use MUST be 0)
audit report written: /tmp/audit-dry.md
```

Generated `audit-dry.md`:

```markdown
# Cyprenit Engine v1.0.0-Beta — PQC Infrastructure Risk Report
...
Maximum Risk Classification: CRITICAL / IMMEDIATE ACTION REQUIRED
```

Acceptance criteria: `overflow=0`, `panics=0`, `pool in-use=0` at shutdown.

## 8. Quick Reference — Flags

| Flag | Default | Description |
|---|---|---|
| `-dry-run` | false | synthetic end-to-end run without eBPF |
| `-pcap <file>` | "" | replay a pcap instead of live capture |
| `-ifindex <n>` | 0 | interface to observe (0 = all) |
| `-report <dur>` | 10s | risk-map print interval |
| `-out <file>` | "" | Markdown audit report path written at shutdown |
| `-duration <dur>` | 0 | 0 = forever; >0 = graceful shutdown after this duration |
| `-workers <n>` | 4 | number of parse workers (raise under saturation) |
| `-queue-depth <n>` | 4096 | bounded queue; full ⇒ counted drop |

---

*Cyprenit Engine v1.0.0-Beta Layer 4 — passive, uninterrupted, provable. After
every change re-run the test commands from Section 2; never ship a build that
is not green.*
