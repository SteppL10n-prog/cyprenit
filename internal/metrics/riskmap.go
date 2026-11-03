// Package metrics aggregates ParsedRecords into the PQC risk map:
// per-destination crypto census + rollups by risk label.
package metrics

import (
	"sort"
	"sync"
	"time"

	"github.com/SteppL10n-prog/cyprenit/internal/parser"
)

// FlowKey identifies an observed destination service.
type FlowKey struct {
	Daddr string
	Dport uint16
}

// Census counts handshake kinds toward one destination.
type Census struct {
	RSAKX   int64
	ECC     int64
	Hybrid  int64
	PurePQC int64
	Unknown int64
	MaxRisk int
}

// recentWindowCap bounds the per-flow timestamp ring used for TPS estimation,
// so long-lived flows cannot grow the risk map without limit (memory-leak
// guard consistent with the pool's bounded-slot contract).
const recentWindowCap = 4096

// tpsWindowSecs is the sliding observation window over which the handshake
// rate (VolumeTPS input of the M04 business-impact translation) is computed.
const tpsWindowSecs = 60.0

// flowState keeps the census plus the bounded recent-timestamp ring needed to
// derive an observed VolumeTPS for a flow. All access happens under Map.mu.
type flowState struct {
	census Census
	recent []int64
}

// volumeTPS estimates the flow's transactions-per-second over the trailing
// tpsWindowSecs window. Deterministic given the ring contents and nowSec:
// fewer than two samples, or a zero-width window, yields 0.
func (f *flowState) volumeTPS(nowSec int64) float64 {
	n := len(f.recent)
	if n < 2 {
		return 0
	}
	last := f.recent[n-1]
	if last <= 0 {
		last = nowSec
	}
	cutoff := last - int64(tpsWindowSecs) + 1
	idx := 0
	for i := n - 1; i >= 0; i-- {
		if f.recent[i] < cutoff {
			idx = i + 1
			break
		}
	}
	count := int64(n - idx)
	window := float64(last - f.recent[idx])
	if window <= 0 {
		return float64(count) / tpsWindowSecs
	}
	return float64(count) / window
}

// Map is the in-memory PQC risk map (thread-safe; sink-friendly).
type Map struct {
	mu      sync.Mutex
	flows   map[FlowKey]*flowState
	rollup  map[string]int64 // kind -> global count
	byLabel map[string]int64 // CRITICAL..NONE -> flow count
}

func NewMap() *Map {
	return &Map{
		flows:   make(map[FlowKey]*flowState),
		rollup:  make(map[string]int64),
		byLabel: make(map[string]int64),
	}
}

// SnapshotView is a value copy of the audit-relevant fields of a parsed
// record. The pipeline releases pooled records as soon as the sink returns,
// so the risk map MUST NOT retain pointers into pool-owned memory; it only
// consumes this immutable copy (taken while the record is still valid).
// TSecs is the capture timestamp (unix seconds) used to derive the M04
// VolumeTPS business-impact input from observed handshake rates.
type SnapshotView struct {
	Daddr     string
	Dport     uint16
	Kind      string
	RiskScore int
	TSecs     int64
}

// View extracts the snapshot for a record; nil-safe.
func View(r *parser.ParsedRecord) SnapshotView {
	if r == nil {
		return SnapshotView{}
	}
	return SnapshotView{
		Daddr:     r.Daddr,
		Dport:     r.Dport,
		Kind:      r.Kind,
		RiskScore: r.RiskScore,
		TSecs:     r.TSecs,
	}
}

// Observe records one analysis result. Safe for concurrent sinks.
func (m *Map) Observe(v SnapshotView) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := FlowKey{Daddr: v.Daddr, Dport: v.Dport}
	f := m.flows[k]
	if f == nil {
		f = &flowState{census: Census{}}
		m.flows[k] = f
	}
	if v.TSecs > 0 {
		f.recent = append(f.recent, v.TSecs)
		if n := len(f.recent); n > recentWindowCap {
			f.recent = append(f.recent[:0], f.recent[n-recentWindowCap:]...)
		}
	}
	c := &f.census
	switch v.Kind {
	case parser.KindRSAKeyExchange:
		c.RSAKX++
	case parser.KindECC:
		c.ECC++
	case parser.KindPQCHybrid:
		c.Hybrid++
	case parser.KindPurePQC:
		c.PurePQC++
	default:
		c.Unknown++
	}
	if v.RiskScore > c.MaxRisk {
		c.MaxRisk = v.RiskScore
	}
	m.rollup[v.Kind]++
}

// Snapshot returns a stable view for export (sorted by descending risk).
type FlowRow struct {
	Key       FlowKey
	Census    Census
	Label     string
	VolumeTPS float64 // observed handshake rate, trailing 60s window (M04)
}

// labelFor maps a numeric risk score onto the global enterprise label set
// defined in internal/parser (single source of truth — no regional wording).
func labelFor(score int) string {
	switch {
	case score >= 100:
		return parser.RiskLabelCritical
	case score >= 70:
		return parser.RiskLabelHigh
	case score >= 30:
		return parser.RiskLabelMedium
	case score >= 10:
		return parser.RiskLabelLow
	default:
		return parser.RiskLabelNone
	}
}

func (m *Map) Snapshot() []FlowRow {
	m.mu.Lock()
	defer m.mu.Unlock()
	nowSec := time.Now().Unix()
	rows := make([]FlowRow, 0, len(m.flows))
	for k, f := range m.flows {
		rows = append(rows, FlowRow{
			Key:       k,
			Census:    f.census,
			Label:     labelFor(f.census.MaxRisk),
			VolumeTPS: f.volumeTPS(nowSec),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Census.MaxRisk != rows[j].Census.MaxRisk {
			return rows[i].Census.MaxRisk > rows[j].Census.MaxRisk
		}
		return rows[i].Key.Daddr < rows[j].Key.Daddr
	})
	return rows
}
