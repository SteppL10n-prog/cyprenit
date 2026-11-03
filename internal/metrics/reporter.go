// Package metrics reporter: deterministic, audit-grade Markdown report engine.
//
// M04 (Business Impact Translation): every ReportRow carries a VolumeTPS
// (transactions-per-second) figure that is translated into a per-minute
// financial loss projection using infrastructure outage and reputation-loss
// coefficients:
//
//	RiskScore == 100 (CRITICAL) -> VolumeTPS * 60 * 450 USD/min
//	RiskScore ==  70 (HIGH)     -> VolumeTPS * 60 * 150 USD/min
//	otherwise                   -> 0
//
// M03 (Material Regulatory Triaging): when at least one CRITICAL finding is
// present, the report is appended with a draft global material-incident and
// compliance notification form (EK-A), including the 72-hour HNDL
// notification clock.
//
// Concurrency contract: GenerateStandardReport is pure over its inputs — it
// holds no shared mutable state and spawns no goroutines, so it cannot widen
// any -race window in the pipeline. It is safe to call concurrently with the
// thread-safe risk map; it only touches the filesystem via the given path.
package metrics

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/SteppL10n-prog/cyprenit/internal/parser"
)

// Loss coefficients (USD per transaction-at-risk per minute), general
// infrastructure outage & reputation-loss model.
const (
	criticalLossPerTxUSD = 450.0
	highLossPerTxUSD     = 150.0
	secondsPerMinute     = 60.0
)

// ReportRow is one audited server-flow entry handed to the report engine.
type ReportRow struct {
	Network        string
	Port           int
	AlgorithmClass string
	RiskScore      int
	PriorityLabel  string
	VolumeTPS      float64 // transactions/sec on this flow (business impact input)
}

// FinancialLossMin returns the per-minute USD loss projection for a row (M04).
// Deterministic pure function of RiskScore and VolumeTPS.
func FinancialLossMin(riskScore int, volumeTPS float64) float64 {
	switch riskScore {
	case 100:
		return volumeTPS * secondsPerMinute * criticalLossPerTxUSD
	case 70:
		return volumeTPS * secondsPerMinute * highLossPerTxUSD
	default:
		return 0
	}
}

// TotalFinancialLossMin sums the per-minute projections across all flows.
func TotalFinancialLossMin(rows []ReportRow) float64 {
	var total float64
	for _, r := range rows {
		total += FinancialLossMin(r.RiskScore, r.VolumeTPS)
	}
	return total
}

type reportRowView struct {
	ReportRow
	FinancialLossMin float64
}

type reportData struct {
	GeneratedUTC    string
	Rows            []reportRowView
	MaxRisk         string
	TotalLossMinUSD float64
	TotalLossFmt    string
	CriticalNets    string
	AppendixA       bool
}

const reportTemplate = `# Cyprenit Engine v1.0.0-Beta — PQC Infrastructure Risk Report

Standard References: DORA Art. 9 & 12 | ISO/IEC 27001:2022 A.8.24 (Cryptographic Controls)

Report Generated (UTC): {{ .GeneratedUTC }}

Maximum Risk Classification: {{ .MaxRisk }}

| Network | Port | Algorithm Class | Risk Score | Priority | Volume (TPS) | Financial Loss Projection (USD/Minute) |
|---------|------|-----------------|------------|----------|--------------|----------------------------------------|
{{- range .Rows }}
| {{ .Network }} | {{ .Port }} | {{ .AlgorithmClass }} | {{ .RiskScore }} | {{ .PriorityLabel }} | {{ printf "%.2f" .VolumeTPS }} | {{ printf "%.2f" .FinancialLossMin }} |
{{- end }}

## TOTAL INFRASTRUCTURE FINANCIAL RISK PROJECTION

{{ .TotalLossFmt }} (aggregate per-minute cost of infrastructure outage and reputational loss across all server flows; M04 Business Impact Translation)
{{ if .AppendixA }}
---

## APPENDIX-A: DRAFT GLOBAL MATERIAL-INCIDENT AND COMPLIANCE NOTIFICATION FORM

**Document No.:** Cyprenit-M03-DRAFT / **Status:** PENDING APPROVAL (not submittable without legal & compliance sign-off)

**Detection Date (UTC):** {{ .GeneratedUTC }}

**Affected Critical Network Segments (RiskScore = 100 / CRITICAL):**
{{ .CriticalNets }}

**Subject:** Detection of post-quantum-insecure (non-PQC) key exchange in TLS handshakes — Harvest Now Decrypt Later (HNDL) data-confidentiality exposure.

**Regulatory Notification Window Warning (72 Hours):** The CRITICAL findings above constitute reasonable suspicion that data traversing the corporate infrastructure is not protected with technically and organisationally adequate cryptographic controls. Under prevailing breach-notification regimes modelled by DORA Art. 12 (obligation to report major ICT-related incidents), the **72-hour notification clock is deemed to have started at the time of detection**. Preparation of a material-incident notification to the competent authorities must begin immediately.

**Draft Compliance Defence Statement (aligned with the general regulatory framework):**

> Our organisation, through continuous passive cryptographic inventory monitoring performed by the Cyprenit Engine v1.0.0-Beta (Layer 4), has detected that certain critical services negotiate RSA-based key exchange at the TLS layer, creating exposure to long-term confidentiality threats of the "harvest now, decrypt later" (HNDL) class. This finding is a proactive risk-reduction observation, not evidence of an active intrusion; no indication of unauthorised access to stored data was identified. As the responsible entity, we have initiated a hybrid post-quantum migration plan (ML-KEM + X25519) to implement the required technical safeguards under DORA Art. 9 (ICT risk management), updated the asset inventory within the scope of ISO/IEC 27001:2022 A.8.24 (cryptographic controls management), and are preserving the complete detection record for audit purposes. Notification procedures have been launched with respect to the 72-hour deadline, and developments will be reported to the competent authorities on a regular basis.

**Attachments:** Flow table above (deterministic evidence record), raw eBPF ring-buffer telemetry archive, ISO/IEC 27001:2022 A.8.24 cryptographic-controls compliance checklist.
{{- end }}
`

func classifyMaxRisk(rows []ReportRow) string {
	var has100, has70, has30, has10 bool
	for _, r := range rows {
		switch r.RiskScore {
		case 100:
			has100 = true
		case 70:
			has70 = true
		case 30:
			has30 = true
		case 10:
			has10 = true
		}
	}
	switch {
	case has100:
		return parser.RiskLabelCritical + " / IMMEDIATE ACTION REQUIRED"
	case has70:
		return parser.RiskLabelHigh + " RISK"
	case has30:
		return parser.RiskLabelMedium + " RISK"
	case has10:
		return parser.RiskLabelLow + " RISK"
	default:
		return "NONE"
	}
}

func hasCritical(rows []ReportRow) bool {
	for _, r := range rows {
		if r.RiskScore == 100 {
			return true
		}
	}
	return false
}

// criticalSegments renders the deterministic APPENDIX-A segment list from CRITICAL
// flows (network:port pairs, sorted lexicographically, deduplicated).
func criticalSegments(rows []ReportRow) string {
	seen := make(map[string]struct{})
	list := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.RiskScore != 100 {
			continue
		}
		entry := fmt.Sprintf("- %s:%d (%s)", r.Network, r.Port, r.AlgorithmClass)
		if _, dup := seen[entry]; dup {
			continue
		}
		seen[entry] = struct{}{}
		list = append(list, entry)
	}
	sort.Strings(list)
	if len(list) == 0 {
		return "- (none)"
	}
	return strings.Join(list, "\n")
}

// GenerateStandardReport writes a deterministic Markdown audit report to
// filePath. The signature is intentionally unchanged so every existing call
// site stays source-compatible while honoring the new VolumeTPS field.
func GenerateStandardReport(filePath string, flows []ReportRow) error {
	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("metrics: template parse: %w", err)
	}

	views := make([]reportRowView, 0, len(flows))
	for _, r := range flows {
		views = append(views, reportRowView{
			ReportRow:        r,
			FinancialLossMin: FinancialLossMin(r.RiskScore, r.VolumeTPS),
		})
	}
	total := TotalFinancialLossMin(flows)

	data := reportData{
		GeneratedUTC:    time.Now().UTC().Format("2006-01-02 15:04:05"),
		Rows:            views,
		MaxRisk:         classifyMaxRisk(flows),
		TotalLossMinUSD: total,
		TotalLossFmt:    fmt.Sprintf("$%.0f / Minute", total),
		CriticalNets:    criticalSegments(flows),
		AppendixA:       hasCritical(flows),
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("metrics: template execute: %w", err)
	}

	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("metrics: create file: %w", err)
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Close()
		return fmt.Errorf("metrics: write report: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("metrics: close report: %w", err)
	}
	return nil
}
