package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"

	"azrbac-auditor/internal/azureauth"
	"azrbac-auditor/internal/graph"
	"azrbac-auditor/internal/rbac"
	"azrbac-auditor/internal/report"
	"azrbac-auditor/internal/rules"
)

func main() {
	_ = godotenv.Load()
	jsonOut := flag.String("json", "azrbac-report.json", "ruta del reporte JSON")
	htmlOut := flag.String("html", "azrbac-report.html", "ruta del reporte HTML")
	flag.Parse()

	cred, err := azureauth.NewCredentials()
	if err != nil {
		fmt.Println("Error de autenticación:", err)
		os.Exit(1)
	}

	subscriptionID, err := azureauth.GetSubscriptionID()
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	ctx := context.Background()

	// Clientes y resolutores
	rbacClient, err := rbac.NewClient(cred, subscriptionID)
	if err != nil {
		fmt.Println("Error creando cliente RBAC:", err)
		os.Exit(1)
	}
	roleResolver, err := rbac.NewRoleResolver(cred, subscriptionID)
	if err != nil {
		fmt.Println("Error creando resolutor de roles:", err)

		os.Exit(1)
	}
	graphClient := graph.NewClient(cred)
	principalResolver := graph.NewResolver(cred)

	fmt.Printf("AzRBAC Auditor — suscripción %s\n\n", subscriptionID)

	assignments, err := rbacClient.ListAll(ctx)
	if err != nil {
		fmt.Println("Error listando asignaciones:", err)
		os.Exit(1)
	}

	// Antes del loop de impresión:
	entries := make([]rules.Entry, 0, len(assignments))

	fmt.Printf("%-50s %-28s %-17s %s\n", "PRINCIPAL", "ROL", "TIPO", "SCOPE")
	fmt.Println(strings.Repeat("-", 120))

	unknowns := 0
	for _, ra := range assignments {
		role := roleResolver.RoleName(ctx, ra.RoleDefinitionID)
		principal := principalResolver.Resolve(ctx, ra.PrincipalID)
		if principal.Type == "Unknown" {
			unknowns++
		}
		fmt.Printf("%-50s %-28s %-17s %s\n",
			principal.Name, role, principal.Type, shortScope(ra.Scope, subscriptionID))

		// Colectar para evaluación
		entries = append(entries, rules.Entry{
			PrincipalID:   ra.PrincipalID,
			PrincipalName: principal.Name,
			PrincipalType: principal.Type,
			RoleName:      role,
			Scope:         shortScope(ra.Scope, subscriptionID),
		})
	}

	if unknowns > 0 {
		fmt.Printf("\n⚠ %d principals sin resolver: verifica en la app los permisos de Graph\n", unknowns)
		fmt.Println("  (User.Read.All y Directory.Read.All, tipo Application, con admin consent)")
	}

	// Evaluación de reglas
	fmt.Println("\n================ AUDITORÍA ================")
	findings := rules.Evaluate(entries)

	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	fmt.Printf("Resumen: %d CRITICAL · %d HIGH · %d MEDIUM\n\n",
		counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"])

	icons := map[string]string{"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
	for _, f := range findings {
		fmt.Printf("%s %s | %s\n", icons[f.Severity], f.Severity, f.Title)
		fmt.Printf("   Principal: %s (%s) | Rol: %s | Scope: %s\n",
			f.Principal, f.PrincipalType, f.Role, f.Scope)
		fmt.Printf("   → %s\n\n", f.Recommendation)
	}
	fmt.Println("\n================ AUDITORÍA AVANZADA ================")
	advancedFindings := rules.EvaluateAdvanced(entries, graphClient)

	for _, f := range advancedFindings {
		findings = append(findings, f) // combinar con hallazgos básicos
	}

	// Re-contar con los nuevos hallazgos
	counts = map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	fmt.Printf("Resumen actualizado: %d CRITICAL · %d HIGH · %d MEDIUM\n\n",
		counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"])

	// Imprimir solo los hallazgos avanzados
	advancedIcons := map[string]string{"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}
	for _, f := range advancedFindings {
		fmt.Printf("%s %s | %s\n", advancedIcons[f.Severity], f.Severity, f.Title)
		fmt.Printf("   Principal: %s (%s) | Rol: %s | Scope: %s\n",
			f.Principal, f.PrincipalType, f.Role, f.Scope)
		fmt.Printf("   → %s\n\n", f.Recommendation)
	}

	rules.SortBySeverity(findings)

	rep := report.New(subscriptionID, findings, entries)

	if err := report.SaveJSON(rep, *jsonOut); err != nil {
		fmt.Println("Error guardando JSON:", err)
	} else {
		fmt.Printf("\nReporte JSON guardado en: %s\n", *jsonOut)
	}

	if err := report.SaveHTML(rep, *htmlOut); err != nil {
		fmt.Println("Error guardando HTML:", err)
	} else {
		fmt.Printf("Reporte HTML guardado en: %s\n", *htmlOut)
	}

}

// shortScope acorta el scope para legibilidad.
func shortScope(scope, subID string) string {
	prefix := "/subscriptions/" + subID
	if scope == prefix {
		return "(subscription)"
	}
	return strings.TrimPrefix(scope, prefix)
}
