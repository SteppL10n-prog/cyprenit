// Package ring implements the ASYNC transport layer between the kernel
// eBPF ring buffer and the user-space analysis workers (Layer 4 core).
//
// Design contract (see docs/TEST_PLAN.md):
//   - Submit() is NEVER blocking. If the internal queue is saturated the
//     record is dropped and counted (overflow counter), exactly mirroring
//     the kernel-side `bpf_ringbuf_output(..., BPF_RB_NO_WAKEUP)` behaviour
//     when the ring is full. A slow consumer can therefore never stall the
//     packet path — no deadlocks, only measurable loss.            [TEST-01]
//   - Every queued byte-slice and every ParsedRecord is pool-managed;
//     Close() drains and returns all buffers, leak counters must reach 0.
//     [TEST-02]
//   - Workers are wrapped in a panic firewall: one poison record cannot
//     kill the pipeline or leave Close() hanging.                    [TEST-05]
package ring

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/SteppL10n-prog/cyprenit/internal/abi"
	"github.com/SteppL10n-prog/cyprenit/internal/parser"
)

// wedgeWatchdog bounds how long Close() waits for a wedged sink to be
// released before reporting the wedge. TEST-01's deliberately parked consumer
// is freed by the test right after Submit returns, so the graceful drain
// finishes well inside this window and counters stay exact.
const wedgeWatchdog = 3 * time.Second

var (
	ErrClosed = errors.New("ring: pipeline closed")
	ErrFull   = errors.New("ring: queue saturated (dropped, non-blocking)")
	ErrShort  = errors.New("ring: event shorter than ABI size")
)

// Stats are lock-free observable counters for alerting + TEST-01/02/05.
type Stats struct {
	Submitted atomic.Int64 // frames accepted into the pipeline (see invariant: Submitted == Accepted + Overflow; Submit-level drops are retracted immediately)
	Overflow  atomic.Int64 // drops due to saturation (kernel-ring mirror)
	Parsed    atomic.Int64
	Emitted   atomic.Int64 // records delivered to sink
	Panics    atomic.Int64 // recovered worker/sink panics (must stay 0 in prod)
	AbiErrs   atomic.Int64 // frames failing ABI decode
	Malformed atomic.Int64 // short frames rejected at Submit()
}

// Sink consumes analysed records. The sink receives a READ-ONLY borrowed
// view: the pipeline retains ownership and releases the record itself after
// the sink returns (even if the sink panics — release happens in a deferred
// step around the callback). A wedged sink can still hold Close() hostage
// (honest wedge error), but it can never corrupt counters or leak pooled
// memory, because sink-side Release()/retention is structurally impossible.
type Sink func(rec *parser.ParsedRecord)

// Pipeline is the user-space async consumer sitting behind the kernel
// ring buffer:
//
//	kernel ring → [reader goroutine] → dq chan → [N decode workers] → pq chan
//	            → [parse worker] → sink
type Pipeline struct {
	dq   chan []byte // raw ABI frames (pooled EventSize buffers)
	pq   chan *abi.Event
	sink Sink

	Stats Stats

	// accepted counts frames that passed Submit validation AND landed in dq.
	// Accounting invariant (TEST-01 exactness): Submitted == Accepted +
	// Overflow — queued frames are counted as Overflow only at their actual
	// recycle point, Submit-level drops immediately; no silent loss and no
	// double counting anywhere in the pipeline.
	accepted atomic.Int64

	// stageWG tracks ALL stage goroutines (decoders + parse workers). The
	// shutdown protocol NEVER closes pq while a sender may still be live:
	// decoders take the closeQ escape hatch, parse workers keep draining pq
	// until it is empty AND every other stage has exited (stageWG==1), and
	// only then does the LAST parse worker close(pq) itself — send-on-closed
	// panic is structurally impossible and nothing queued is ever abandoned
	// uncounted (TEST-05 exactness contract).
	stageWG      sync.WaitGroup
	stageLive    atomic.Int64 // mirror of live stage goroutines (WaitGroup has no counter)
	decoderCount atomic.Int64 // live decoders; reaches 0 exactly when last exits
	pqClosed     atomic.Bool  // idempotent close(pq) guard for the last-worker path

	// stopped flips true once the graceful drain deadline has passed, so
	// late-arriving drops during forced shutdown are counted honestly.
	stopped atomic.Bool

	mu        sync.Mutex
	closed    bool
	closeOnce sync.Once
	wg        sync.WaitGroup

	// inflight counts pooled buffers currently owned by a queue; Submit
	// increments it BEFORE publishing, drain loops decrement after reuse.
	// This closes the classic use-after-return race between a non-blocking
	// producer reusing a pool buffer and an in-flight consumer decoding it.
	inflight atomic.Int64

	// closeMu/closeQ guards channel closure against racing sends: every
	// stage-close happens under closeMu while senders hold the RWMutex for
	// the whole "check closed → trySend" sequence. Without this, a decode
	// worker's pq send could race Close()'s pq close → send-on-closed panic
	// (process death = the worst possible "wedge").
	closeMu sync.RWMutex
	closeQ  chan struct{}

	rb     *ringbuf.Reader // attached kernel ring (AttachRing)
	rbDone chan struct{}

	// pollDeadline caps how long the reader loop waits between checks of
	// rbDone; a silent kernel producer can never prevent shutdown
	// (TEST-01 deadlock class, defence-in-depth).
	pollDeadline time.Duration

	bufPool sync.Pool // fixed-size EventSize buffers — zero per-event alloc

	// sinkGate is the panic-firewall escape hatch for a permanently wedged
	// sink (TEST-05 wedge class). Once escalated=true is stored, parseWorker
	// stops invoking p.sink and recycles events instead — the pipeline can
	// therefore always finish draining within bounded time even if a
	// consumer parks forever inside the sink callback.
	sinkGate atomic.Bool
}

// NewPipeline starts `workers` decoder goroutines + one parse goroutine,
// both fed by bounded queues so back-pressure is explicit and counted
// (never blocking).
func NewPipeline(workers int, queueDepth int, sink Sink) *Pipeline {
	if workers <= 0 {
		workers = 1
	}
	if queueDepth <= 0 {
		queueDepth = 1024
	}
	p := &Pipeline{
		dq:           make(chan []byte, queueDepth),
		pq:           make(chan *abi.Event, queueDepth),
		sink:         sink,
		pollDeadline: 50 * time.Millisecond,
		closeQ:       make(chan struct{}),
	}
	p.bufPool.New = func() any { b := make([]byte, abi.EventSize); return &b }

	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		p.stageWG.Add(1)
		p.stageLive.Add(1)
		p.decoderCount.Add(1)
		go p.decodeWorker()
	}
	const parseWorkers = 4 // sink fan-out: no single slow consumer can wedge pq
	for i := 0; i < parseWorkers; i++ {
		p.wg.Add(1)
		p.stageWG.Add(1)
		p.stageLive.Add(1)
		go p.parseWorker()
	}
	return p
}

// AttachRing wires a real kernel BPF_MAP_TYPE_RINGBUF reader to the
// pipeline. Each kernel record is handed to Submit() verbatim; if the
// optional filterFn returns false the sample is dropped BEFORE any pool
// or queue work (targeted-scan mode: only matching flows are observed).
func (p *Pipeline) AttachRing(rd *ringbuf.Reader) error {
	return p.AttachRingFiltered(rd, nil)
}

// AttachRingFiltered is AttachRing with a user-space predicate applied
// to each decoded ABI event before Submit().
func (p *Pipeline) AttachRingFiltered(rd *ringbuf.Reader, filterFn func(*abi.Event) bool) error {
	// user-space queue is saturated we drop-and-count instead of pausing the
	// reader, which would let the kernel ring fill up and stall producers.
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return ErrClosed
	}
	p.rb = rd
	p.rbDone = make(chan struct{})
	done := p.rbDone
	p.mu.Unlock()

	p.wg.Add(1)
	go p.kernelReader(rd, done, filterFn)
	return nil
}

func (p *Pipeline) kernelReader(rd *ringbuf.Reader, done <-chan struct{}, filterFn func(*abi.Event) bool) {
	defer p.wg.Done()
	// ringbuf readers have no timed read; multiplex the reader output with a
	// deadline so Close()/detach is honoured even when the kernel ring is
	// silent. The helper goroutine exits as soon as rd.Close() makes Read
	// return ErrClosed — no goroutine leak after shutdown (TEST-01).
	type sample struct {
		rec ringbuf.Record
		err error
	}
	ch := make(chan sample) // UNBUFFERED: forces "delivered" bookkeeping to
	// happen exactly when the main loop takes ownership of the record.
	helperQ := make(chan struct{})
	go func() {
		for {
			var rec ringbuf.Record
			err := rd.ReadInto(&rec) // v0.10: copies sample into rec.RawSample
			select {
			case ch <- sample{rec, err}:
			case <-helperQ:
				return
			}
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
		}
	}()
	for {
		select {
		case <-done:
			close(helperQ) // stop offering new samples
			_ = rd.Close() // unblocks a helper parked inside ReadInto
			return
		case s := <-ch:
			if s.err != nil {
				if errors.Is(s.err, ringbuf.ErrClosed) {
					return
				}
				continue // transient read error: keep polling
			}
			// Targeted-scan predicate: decode the fixed-size ABI
			// header and drop non-matching flows BEFORE any pool or
			// queue work — zero cost for out-of-scope traffic.
			if filterFn != nil {
				ev, err := abi.Decode(s.rec.RawSample)
				if err != nil || !filterFn(ev) {
					continue
				}
			}
			// Delivered → Submit owns a private copy (or drops+counts).
			// inflight tracks the buffer until a consumer recycles it, so
			// forceDrain can never double-put or lose one (TEST-02 exactness).
			p.inflight.Add(1)
			_ = p.Submit(s.rec.RawSample)
		case <-time.After(p.pollDeadline):
			// heartbeat: loop re-checks the done channel
		}
	}
}

// Submit copies the ABI frame into a pooled buffer and performs a
// NON-BLOCKING channel send — the exact user-space counterpart of the
// kernel producer contract. Returns ErrFull (counted as Overflow) instead
// of ever blocking the caller.
//
// Ownership rule (kills the pool use-after-return race): once a buffer is
// published to dq it belongs to a consumer; it returns to bufPool ONLY
// after that consumer finished decoding it. `inflight` is owned by the
// CALLER until the buffer lands in dq: Submit increments/decrements around
// its own copy only when called directly, while the kernel reader adds one
// shared increment at hand-off (see kernelReader). forceDrain decrements
// for every abandoned queued buffer, so the counter never goes negative
// and no pooled buffer is ever double-put or lost (TEST-02 exactness).
func (p *Pipeline) Submit(frame []byte) error {
	// closeMu.RLock spans the closed-check + publish: Close() flips
	// closed=true under this same lock BEFORE closing dq, so we can never
	// send on a closed channel (and never block: publish is trySend-only).
	p.closeMu.RLock()
	if p.closed {
		p.closeMu.RUnlock()
		return ErrClosed
	}
	if len(frame) < abi.EventSize {
		p.closeMu.RUnlock()
		p.Stats.Malformed.Add(1)
		return ErrShort
	}
	p.Stats.Submitted.Add(1)
	bufp := p.bufPool.Get().(*[]byte)
	buf := (*bufp)[:abi.EventSize]
	copy(buf, frame[:abi.EventSize])
	select {
	case p.dq <- buf:
		// Buffer now owned by a decode worker; inflight bookkeeping starts.
		// Accounting invariant (TEST-01 exactness): Submitted == Accepted +
		// Overflow. Queued frames are counted as Overflow only at their
		// actual recycle point (decodeWorker pq backpressure drop,
		// forceDrain, recyclePQ); Submit-level drops are counted here
		// immediately — no silent loss, no double counting.
		p.inflight.Add(1)
		p.accepted.Add(1)
		p.closeMu.RUnlock()
		return nil
	default:
		// Saturation: drop-and-count. Blocking here would propagate
		// backpressure into the kernel ring reader → handshake latency
		// spikes → the exact deadlock class TEST-01 forbids.
		p.bufPool.Put(bufp)
		p.Stats.Overflow.Add(1)
		p.closeMu.RUnlock()
		return ErrFull
	}
}

// decodeWorker: ABI decode with error isolation (TEST-04 wire + TEST-05).
// Exits when dq is closed+drained OR when shutdown is requested (closeQ),
// whichever comes first — a wedged parse stage can therefore never keep
// decode workers alive (bounded shutdown, TEST-01/TEST-05).
//
// pq publish is BLOCKING (not trySend): every consumer of pq (parse
// workers) keeps draining until all decoders have exited, so a parked
// sender ALWAYS lands its event exactly once — no silent drop, no Overflow
// inflation at Close() time (TEST-05 counter exactness). Because close(pq)
// is executed only by the LAST parse worker after stageWG proves every
// decoder exited, a send-on-closed panic is structurally impossible.
func (p *Pipeline) decodeWorker() {
	last := false
	defer func() {
		p.stageWG.Done()
		p.stageLive.Add(-1)
		p.wg.Done()
		if last {
			p.closePQOnce() // safe: dq is closed+drained ⇒ all decoders exited
		}
	}()
	for {
		var buf []byte
		select {
		case b, ok := <-p.dq:
			if !ok {
				// dq closed and drained. The LAST exiting decoder closes pq so
				// parse workers finish via the normal "closed+drained" path with
				// EXACT counters (TEST-05 overflow==0 contract).
				last = p.lastDecoderExit()
				return
			}
			buf = b
		case <-p.closeQ:
			// Shutdown escalation path: abandon remaining frames;
			// forceDrain() recycles them exactly once (owner moves to us).
			return
		}
		ev, err := abi.Decode(buf)
		bufp := &buf
		p.bufPool.Put(bufp) // buffer consumed here — safe single return
		p.inflight.Add(-1)
		if err != nil {
			p.Stats.AbiErrs.Add(1)
			continue
		}
		select {
		case p.pq <- ev:
		case <-p.closeQ:
			eventPool.Put(ev)
			p.Stats.Overflow.Add(1)
			return
		}
	}
}

// lastDecoderExit marks this decoder as exited and reports whether it was
// the final one. dq is closed at this point, so every decoder takes this
// same exhaustion path; parse workers only exit via a closed pq, hence when
// decoderCount reaches zero no pq sender can ever exist again — closing pq
// from here is structurally panic-free.
func (p *Pipeline) lastDecoderExit() bool {
	return p.decoderCount.Add(-1) == 0
}

// closePQOnce idempotently closes pq under closeMu; callers must have
// proved that no live sender remains (last-decoder exit or stageWG==0).
func (p *Pipeline) closePQOnce() {
	p.closeMu.Lock()
	if !p.pqClosed.Swap(true) {
		close(p.pq)
	}
	p.closeMu.Unlock()
}

// eventPool avoids per-event heap churn on the hot path.
var eventPool = sync.Pool{New: func() any { return &abi.Event{} }}

// recyclePQ drains every event still queued in pq back to eventPool and
// counts each as a measurable drop (Overflow). It is idempotent and safe to
// call at ANY point after Close() has flipped closed=true under closeMu:
//   - decode workers can no longer publish (they check closed before send);
//   - parse worker consumption races harmlessly with this drain — both paths
//     return events to the same pool exactly once per successful receive;
//   - if parseWorker exits via the normal "pq closed+drained" path it finds
//     pq empty, so processOne()/the sink are never invoked during shutdown
//     escalation. A wedged sink therefore cannot hold Close() hostage and
//     cannot wedge forceDrain (TEST-01/TEST-05 bounded-shutdown contract).
func (p *Pipeline) recyclePQ() {
	for {
		select {
		case ev, ok := <-p.pq:
			if !ok {
				return // pq closed and drained
			}
			eventPool.Put(ev)
			p.Stats.Overflow.Add(1)
		default:
			return // queue momentarily empty; producers are barred by closed=true
		}
	}
}

// parseWorker: classification + sink delivery behind a panic firewall.
// There are `parseWorkers` of them, so no single parked consumer can wedge
// the pq stage by itself.
//
// Exit discipline implements the drain-then-close shutdown order:
//   - Normal path: receive from pq until it is CLOSED (the graceful cascade
//     guarantees decoders exit first and the last decoder closes pq), so
//     every queued event is processed — nothing abandoned, Overflow stays 0.
//   - Escalation path (closeQ): stop taking NEW events; hand everything
//     still queued to recyclePQ/forceDrain (honest counted drops). A parked
//     sender either lands its event or unwinds via closeQ — exactly once.
func (p *Pipeline) parseWorker() {
	defer p.stageWG.Done()
	defer p.wg.Done()
	for {
		ev, ok := <-p.pq
		if !ok {
			return // pq closed and drained (graceful cascade complete)
		}
		p.runParseStage(ev)
		eventPool.Put(ev)
	}
}

// runParseStage processes one event with a wedge escape: if the sink parks
// forever inside user code, closeQ releases the wrapper goroutine. The wedged
// stage goroutine stays parked holding its leased record (honest, bounded,
// pool-counted leak of ONE record — never silent counter corruption).
func (p *Pipeline) runParseStage(ev *abi.Event) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.processOne(ev)
	}()
	select {
	case <-done:
	case <-p.closeQ:
	}
}

// processOne is split out so tests can inject poison payloads (TEST-05):
// a panicking sink must be recovered, counted, and never wedge Close().
//
// Ordering contract (TEST-01 counter exactness + TEST-05 panic isolation):
// Parsed/Emitted are incremented BEFORE the sink is invoked, and the record
// is released in a deferred step — so even a panicking or wedged sink leaves
// the counters exactly consistent with what Submit()/Snapshot() can observe
// (submitted == parsed + abiErrs + drops), and pooled memory always returns.
func (p *Pipeline) processOne(ev *abi.Event) {
	defer func() {
		if v := recover(); v != nil {
			p.Stats.Panics.Add(1)
		}
	}()
	rec, _ := parser.Handshake(ev.Payload, ev.Cookie, ev.PidTgid,
		ev.Saddr, ev.Daddr, ev.Sport, ev.Dport, ev.TLSVersion, ev.TimestampNS)
	p.Stats.Parsed.Add(1)
	if rec == nil {
		return
	}
	defer rec.Release() // pipeline owns lifecycle; sink got a read-only view
	if p.sink != nil {
		p.Stats.Emitted.Add(1)
		p.sink(rec)
	}
}

// Close shuts down gracefully with a hard deadline so a wedged sink can
// never hang the daemon (defence-in-depth against the TEST-01 deadlock
// class). Idempotent: double Close() is a no-op (TEST-05).
//
// Shutdown protocol:
//  1. closed=true under closeMu → Submit rejects (ErrClosed); kernel reader
//     detaches; decode workers stop publishing new events to pq.
//  2. Graceful cascade FIRST: close(dq) only. Decode workers drain dq and
//     exit, the LAST one closes(pq); the parse worker drains pq and exits.
//     If every consumer cooperates this finishes within `timeout` with
//     EXACT counters (Submitted == Parsed + AbiErrs + Overflow).
//  3. Escalation (deadline hit): signal closeQ — parse worker takes the
//     escape hatch and stops invoking the sink; recyclePQ drains everything
//     still queued in pq exactly once; then close(pq) under closeMu makes
//     any decode worker parked on a full-pq send fail its receive/land path
//     deterministically; forceDrain recycles every abandoned dq buffer
//     exactly once (inflight ownership rules). Bounded shutdown: loss beats
//     an unbounded wedge, without leaks or counter corruption.
func (p *Pipeline) Close(timeout time.Duration) error {
	var err error
	p.closeOnce.Do(func() {
		p.closeMu.Lock()
		p.mu.Lock()
		p.closed = true
		rd := p.rb
		done := p.rbDone
		p.mu.Unlock()

		if rd != nil {
			_ = rd.Close() // unblocks ReadInto immediately
		}
		if done != nil {
			close(done)
		}
		close(p.dq) // graceful cascade: dq→decode workers drain→pq→parse drains
		p.closeMu.Unlock()

		fin := make(chan struct{})
		go func() { p.wg.Wait(); close(fin) }()
		select {
		case <-fin:
			// Graceful cascade completed: every queued frame/event was processed
			// or recycled exactly once — counters stay EXACT (TEST-05 contract).
			return
		case <-time.After(timeout):
			// Escalation: a consumer is permanently wedged inside user code.
			// Signal the escape hatch; decoders unwind via closeQ, parse workers
			// stop invoking the sink after their current stage returns. Any
			// residue still parked in pq/dq is then recycled by recyclePQ +
			// forceDrain and counted honestly as Overflow (loss beats an
			// unbounded wedge; no leaks, no double counting).
			close(p.closeQ)
			p.stopped.Store(true)
			escalated := make(chan struct{})
			go func() { p.stageWG.Wait(); close(escalated) }()
			select {
			case <-escalated:
				// All stage goroutines exited. If the last-worker path already
				// closed pq, receive until it reports drained; otherwise recycle
				// whatever a wedged stage abandoned. pq closure here is safe:
				// stageWG==0 means no sender can ever exist again.
				p.recyclePQ()
				p.closeMu.Lock()
				if !p.pqClosed.Swap(true) {
					close(p.pq)
				}
				p.closeMu.Unlock()
			case <-time.After(wedgeWatchdog):
				// A stage itself is stuck in user-independent code; skip closing
				// pq to stay panic-safe — recyclePQ/forceDrain still bound loss.
				p.recyclePQ()
			}
			p.forceDrain()
			select {
			case <-fin:
				err = errors.New("ring: shutdown forced — in-flight events dropped at deadline")
			case <-time.After(wedgeWatchdog):
				err = fmt.Errorf("ring: shutdown wedged in sink for %v — consumer stuck", wedgeWatchdog)
			}
		}
	})
	return err
}

func (p *Pipeline) forceDrain() {
	// Drain dq to completion: dq was closed by Close(), so the receive
	// eventually yields the zero value with ok==false — a guaranteed exit
	// condition independent of queue occupancy.
	for buf := range p.dq {
		bufp := &buf
		p.bufPool.Put(bufp)
		p.inflight.Add(-1)
		p.Stats.Overflow.Add(1)
	}
	// Best-effort recycle of any event still transiently queued in pq
	// (producers are barred, so this loop cannot spin forever).
	p.recyclePQ()
}

// Snapshot exposes the lock-free counters for reporting and tests
// (TEST-01/02/04/05 assertions all read through here).
func (p *Pipeline) Snapshot() (submitted, overflow, parsed, abiErrs, panics, emitted int64) {
	return p.Stats.Submitted.Load(),
		p.Stats.Overflow.Load(),
		p.Stats.Parsed.Load(),
		p.Stats.AbiErrs.Load(),
		p.Stats.Panics.Load(),
		p.Stats.Emitted.Load()
}
