# Cyprenit Engine v1.0.0-Beta — Layer 4: Async eBPF Passive Discovery Prototype
## Critical Unit Test Plan (Contracts Defined Before Implementation — TDD)

**Threat model:** this prototype runs *non-invasively* inside general corporate
infrastructure data centers. The two largest production risks are:

1. **Deadlock / performance wedge:** if the consumer blocks during the
   kernel→user-space ring-buffer transfer, the producer (eBPF
   `bpf_ringbuf_output`) stalls the kernel datapath; TLS handshake latency
   increases → network traffic is disrupted. Additionally, if a parser
   goroutine panics while processing a packet, the channel closes and the whole
   pipeline dies.
2. **Memory leak:** failing to release ring records (`[]byte`) or extracted
   record structs (`ParsedRecord`) causes RSS to grow linearly in a long-lived
   daemon.

Therefore the **5 critical scenarios** below were written as contracts BEFORE
the implementation code and are verified with `go test`.

### TEST-01 — Deadlock / Backpressure: Submit() Must Never Block
**Goal:** the producer must never block; when the consumer is slow, records
drop but the system never wedges.
**Steps:**
- Start the pipeline with 10 KiB rings (capacity = 8192 bytes → ~2 records fit).
- Send 10,000 records concurrently from 50 producer goroutines.
- Never read from the consumer (worst case: user space hung).
**Acceptance criteria:**
- `Submit()` never blocks under any condition; all calls return within < 5 s total.
- Overflow counter == exactly the expected drop count (NO silent loss, measurable loss only).
- `Close()` returns without deadlock in ≤ 5 s (goroutine leaks are caught here:
  active goroutine count must fall back to baseline at shutdown).
**Kernel counterpart:** `BPF_RB_NO_WAKEUP` plus a dedicated reader goroutine on
the user side; when the ring is full `bpf_ringbuf_output` returns `NULL` → the
drop counter increments and the packet path NEVER stalls.

### TEST-02 — Memory Leak: ParsedRecord Pool Must Return Every Record
**Goal:** every struct taken from the object pool (sync.Pool-like) must be
returned; no leakage outside the pool at shutdown.
**Steps:**
- Parse 10,000 fake TLS ClientHello records → acquire `ParsedRecord` → consume → `Release()`.
- Inspect the pool's outstanding-acquisition counters.
**Acceptance criteria:**
- `InUse() == 0`, `Leaked() == 0`, `Peak() <= 2*numCPU` (only transient per-worker records).
- When 100 un-released records are simulated, `Leaked() == 100` (the detector is
  not blind: it must actually work).

### TEST-03 — Misclassification Boundary Cases: Cipher Suite Detection Accuracy
**Goal:** the core of the PQC risk map — correct cipher-suite detection.
**Inputs (real RFC 8446 wire format):**
- ClientHello #1: static-RSA key exchange suites only → `rsa_kx`, score 100 (CRITICAL).
- ClientHello #2: `TLS_AES_128_GCM_SHA256 (0x1301)` + classical curves in the
  `key_share` extension → `ecc`, score 70 (HIGH).
- ClientHello #3/#4: hybrid (X25519MLKEM768) and pure-PQC groups → scores 30/10.
- Case-fuzz: byte-swapped / truncated variants of the same inputs → `unknown`, NEVER a panic.
**Acceptance criteria:**
`detectPQRisk()` ordering: `rsa_kx > ecc > hybrid > pure-PQC` (risk score 100..10).

### TEST-04 — Kernel/User Wire-Format Compatibility (ABI): Go binary ↔ eBPF C Struct
**Goal:** guarantee the raw bytes coming from the ring buffer match the C-side
`struct cyprenit_evt` byte-for-byte (wrong offset = corrupted map = silent data loss).
**Steps:**
- Encode a reference record with fixed constants → compare against a pinned hex golden vector.
- Decode the golden vector → assert field-by-field equality.
- Verify the use of the pinned constant `EventSize = 128` instead of `unsafe.Sizeof`;
  short/oversized buffers must return errors, never panic.
**Acceptance criteria:** golden hex vector pinned; a `binary.Size(struct)` check
breaks ABI regressions at compile/test time.

### TEST-05 — Stress + Panic Isolation + Graceful Shutdown
**Goal:** 1000 events × 8 workers; even if one worker panics the others keep
running, `Close()` rejects later `Submit()` calls, double `Close()` is idempotent.
**Steps:**
- Run under stress; call `Stop()` mid-flight; then try a new `Submit()`.
**Acceptance criteria:**
- A poisoned record is reported as `ErrPoison`; the worker does not die (recover wrapper).
- `Submit()` after `Stop()` → `ErrClosed`, no blocking.
- Double `Close()` produces no panic/error. All tests green under `-race`.

## Running

```bash
go build ./... && go vet ./...
go test -race -count=1 ./...
```

> Note: loading the eBPF program (`tls_probe.bpf.c`) requires root plus a
> kernel ≥ 5.8 with BTF. In the CI container (kernel 4.19) the loader runs in
> "dry-run" mode; therefore the unit tests above are NOT dependent on the
> kernel — parser, ring and ABI are exercised in isolation.
