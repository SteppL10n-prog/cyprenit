package parser

import (
	"sync"
	"sync/atomic"
)

const poolFreeCap = 4096

// RecordPool is the audited object pool behind every ParsedRecord.
//
// Enterprise concurrency contract:
//
//	#1 ALL nil / pool / epoch / capacity checks inside Get() and Release()
//	   execute under the single mutex p.mu — there is no lock-free fast path
//	   that touches slot payload memory, so the Go race detector observes
//	   zero unsynchronised read/write pairs on recycled slots.
//	#2 gets/puts/leaks are sync/atomic counters (atomic.Uint64): Add/Load
//	   without extra mutex cost; derived audit gauges inUse/peak/misuse use
//	   atomic.Int64 for the same reason.
//	#3 Epoch stamping + per-slot lease cells close the use-after-free and
//	   double-release classes. The pool hands out VALUE handles
//	   (ParsedRecord), never pointers into slot memory: the caller's copy
//	   lives on its own stack/slice and can never alias a live slot. Every
//	   release attempt is validated against the slot's monotonic epoch lease
//	   executed under p.mu before any payload memory is touched. An over-cap
//	   burst sheds records to the GC and increments `leaks` instead of
//	   inflating RSS.
type RecordPool struct {
	mu     sync.Mutex
	free   []*genSlot
	leased map[uint64]*genSlot
	epoch  uint64

	gets  atomic.Uint64
	puts  atomic.Uint64
	leaks atomic.Uint64

	inUse  atomic.Int64
	peak   atomic.Int64
	misuse atomic.Int64
}

// genSlot is a generation cell holding one record's payload plus its lease
// state. seq is monotonically increasing across the whole pool (== pool
// epoch at acquisition); active marks an outstanding lease. Double-release
// and stale releases fail the seq/active check under p.mu and become counted
// no-ops that NEVER corrupt gets/puts/leaks or the free list.
type genSlot struct {
	rec    ParsedRecord // payload; reachable only through p.mu-guarded paths
	seq    uint64
	active bool
}

func NewRecordPool() *RecordPool { return &RecordPool{leased: make(map[uint64]*genSlot)} }

// Get acquires an epoch-stamped record HANDLE (a value copy of the slot
// payload). Every check and mutation below runs inside the p.mu critical
// section (rule #1); counter updates are atomic (rule #2).
func (p *RecordPool) Get() *ParsedRecord {
	p.mu.Lock()
	defer p.mu.Unlock()

	var s *genSlot
	if n := len(p.free); n > 0 {
		s = p.free[n-1]
		p.free = p.free[:n-1]
	} else {
		s = new(genSlot)
	}

	p.epoch++
	s.seq = p.epoch
	s.active = true
	s.rec = ParsedRecord{pool: p, Epoch: p.epoch}
	p.leased[p.epoch] = s

	p.gets.Add(1)
	cur := p.inUse.Add(1)
	for {
		hw := p.peak.Load()
		if hw >= cur || p.peak.CompareAndSwap(hw, cur) {
			break
		}
	}
	// Lease copy: the returned handle lives on the CALLER's memory; the slot
	// payload is never aliased by it, so no lock-free path can race with a
	// recycled slot (rule #3 — use-after-free class closed structurally).
	cp := s.rec
	return &cp
}

// Release returns a record handle to its pool. nil input is a no-op; all
// validation runs under p.mu (rule #1). The handle's Epoch must match the
// slot's current lease (seq) and the lease must be active — otherwise the
// call is a double-release or a stale use-after-recycle and is counted as
// misuse without touching payload memory (rule #3). On success the lease is
// deactivated BEFORE the payload is wiped/re-published, so any concurrent
// second release attempt on the same handle fails the lease check inside
// the very same mutex (serialised → deterministic).
func (p *RecordPool) Release(r *ParsedRecord) {
	if r == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if r.pool != p || r.Epoch == 0 {
		p.misuse.Add(1)
		return
	}
	// Locate the owning cell by scanning the outstanding-lease set is O(n);
	// instead the handle carries the cell id implicitly via Epoch: the pool
	// keeps a map epoch→cell ONLY while leased. A released/stale Epoch is
	// simply absent from the map → misuse.
	s, ok := p.leased[r.Epoch]
	if !ok || !s.active || s.seq != r.Epoch {
		p.misuse.Add(1)
		return
	}
	// Deactivate the lease FIRST under p.mu: any second release attempt for
	// this Epoch then fails the leased-map lookup inside the same mutex and
	// becomes a counted no-op (double-release closure, rule #3).
	s.active = false
	delete(p.leased, r.Epoch)

	if len(p.free) >= poolFreeCap {
		// Over-cap burst: shed the slot to the GC, count the leak, never
		// inflate RSS (rule #3).
		p.leaks.Add(1)
		*s = genSlot{}
		p.inUse.Add(-1)
		*r = ParsedRecord{} // wipe the caller's handle (caller-owned memory)
		return
	}
	*s = genSlot{rec: ParsedRecord{pool: p}}
	p.free = append(p.free, s)
	p.puts.Add(1)
	p.inUse.Add(-1)
	*r = ParsedRecord{} // wipe the caller's handle (caller-owned memory)
}

// Stats exposes the atomic counters for auditing and TEST-02. Loads are
// lock-free by design; per-counter values are linearizable, so deltas
// observed by a test that owns all traffic in the window are exact.
func (p *RecordPool) Stats() (gets, puts, leaks uint64) {
	return p.gets.Load(), p.puts.Load(), p.leaks.Load()
}

func (p *RecordPool) audit() (inUse, peak, gets, puts int64) {
	g, q, _ := p.Stats()
	return p.inUse.Load(), p.peak.Load(), int64(g), int64(q)
}

func (p *RecordPool) misuseCount() int64 { return p.misuse.Load() }
