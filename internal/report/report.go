package report

import (
	"encoding/json"
	"html/template"
	"os"
	"time"

	"azrbac-auditor/internal/rules"
)

// AuditReport es la foto exportable de una auditoría.
type AuditReport struct {
	GeneratedAt    time.Time       `json:"generated_at"`
	SubscriptionID string          `json:"subscription_id"`
	Summary        map[string]int  `json:"summary"`
	Findings       []rules.Finding `json:"findings"`
	Entries        []rules.Entry   `json:"role_assignments"`
}

// New construye el reporte y calcula el resumen por severidad.
func New(subscriptionID string, findings []rules.Finding, entries []rules.Entry) AuditReport {
	counts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return AuditReport{
		GeneratedAt:    time.Now(),
		SubscriptionID: subscriptionID,
		Summary:        counts,
		Findings:       findings,
		Entries:        entries,
	}
}

// SaveJSON escribe el reporte en JSON indentado.
func SaveJSON(r AuditReport, path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

const htmlTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AzRBAC Auditor Report</title>
<style>
  body { font-family: "Segoe UI", Arial, sans-serif; margin: 2rem; background: #f6f8fa; color: #24292f; }
  h1 { margin-bottom: 0.2rem; }
  code { background: #eaeef2; padding: 0.1rem 0.35rem; border-radius: 4px; font-size: 0.85em; }
  .cards { display: flex; gap: 1rem; margin: 1.5rem 0; flex-wrap: wrap; }
  .card { padding: 1rem 1.6rem; border-radius: 10px; color: #fff; font-weight: 700; font-size: 1.05rem; }
  .card.CRITICAL { background: #c0392b; }
  .card.HIGH { background: #e67e22; }
  .card.MEDIUM { background: #f1c40f; color: #24292f; }
  table { border-collapse: collapse; width: 100%; background: #fff; margin-bottom: 2rem; }
  th, td { padding: 0.55rem 0.8rem; border: 1px solid #d0d7de; text-align: left; font-size: 0.88rem; vertical-align: top; }
  th { background: #eaeef2; }
  .badge { padding: 0.15rem 0.55rem; border-radius: 999px; color: #fff; font-size: 0.72rem; font-weight: 700; white-space: nowrap; }
  .badge.CRITICAL { background: #c0392b; }
  .badge.HIGH { background: #e67e22; }
  .badge.MEDIUM { background: #f1c40f; color: #24292f; }
</style>
</head>
<body>
<h1>🛡️ AzRBAC Auditor — IAM Audit Report</h1>
<p>Subscription: <code>{{.SubscriptionID}}</code> · Generated: {{.GeneratedAt.Format "2006-01-02 15:04:05"}}</p>

<div class="cards">
  <div class="card CRITICAL">{{index .Summary "CRITICAL"}} CRITICAL</div>
  <div class="card HIGH">{{index .Summary "HIGH"}} HIGH</div>
  <div class="card MEDIUM">{{index .Summary "MEDIUM"}} MEDIUM</div>
</div>

<h2>Findings ({{len .Findings}})</h2>
<table>
  <tr><th>Severity</th><th>Finding</th><th>Principal</th><th>Type</th><th>Role</th><th>Scope</th><th>Recommendation</th></tr>
  {{range .Findings}}
  <tr>
    <td><span class="badge {{.Severity}}">{{.Severity}}</span></td>
    <td>{{.Title}}</td>
    <td>{{.Principal}}</td>
    <td>{{.PrincipalType}}</td>
    <td>{{.Role}}</td>
    <td><code>{{.Scope}}</code></td>
    <td>{{.Recommendation}}</td>
  </tr>
  {{end}}
</table>

<h2>Role assignments reviewed ({{len .Entries}})</h2>
<table>
  <tr><th>Principal</th><th>Type</th><th>Role</th><th>Scope</th></tr>
  {{range .Entries}}
  <tr>
    <td>{{.PrincipalName}}</td>
    <td>{{.PrincipalType}}</td>
    <td>{{.RoleName}}</td>
    <td><code>{{.Scope}}</code></td>
  </tr>
  {{end}}
</table>
</body>
</html>`

// SaveHTML renderiza el reporte con html/template.
func SaveHTML(r AuditReport, path string) error {
	t, err := template.New("report").Parse(htmlTmpl)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return t.Execute(f, r)
}
