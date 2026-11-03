package parser

// Global enterprise risk labels (Phase-2 standardisation). These constants
// are the single source of truth for every classification output; they carry
// no regional or sector-specific wording and are consumed verbatim by the
// log exporter, the risk map rollups and the audit report engine.
const (
	RiskLabelCritical = "CRITICAL"
	RiskLabelHigh     = "HIGH"
	RiskLabelMedium   = "MEDIUM"
	RiskLabelLow      = "LOW"
	RiskLabelNone     = "NONE"
)
