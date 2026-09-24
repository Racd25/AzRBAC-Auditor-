package rules

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"azrbac-auditor/internal/graph"
)

type Entry struct {
	PrincipalID   string
	PrincipalName string
	PrincipalType string
	RoleName      string
	Scope         string
}

type Finding struct {
	Severity       string
	Title          string
	Principal      string
	PrincipalType  string
	Role           string
	Scope          string
	Recommendation string
}

var privilegedRoles = map[string]string{
	"Owner":                     "CRITICAL",
	"User Access Administrator": "CRITICAL",
	"Role Based Access Control Administrator": "CRITICAL",
	"Contributor": "HIGH",
}

var severityOrder = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

func Evaluate(entries []Entry) []Finding {
	var findings []Finding

	for _, e := range entries {
		baseSev, isPriv := privilegedRoles[e.RoleName]

		if isPriv {
			findings = append(findings, Finding{
				Severity:       baseSev,
				Title:          "Privileged role assigned",
				Principal:      e.PrincipalName,
				PrincipalType:  e.PrincipalType,
				Role:           e.RoleName,
				Scope:          e.Scope,
				Recommendation: "Validate business need; prefer just-in-time via PIM and scope to resource group, not subscription.",
			})
		}

		if isPriv && e.PrincipalType == "User" {
			findings = append(findings, Finding{
				Severity:       "HIGH",
				Title:          "Privileged role assigned directly to a user (should be via group)",
				Principal:      e.PrincipalName,
				PrincipalType:  e.PrincipalType,
				Role:           e.RoleName,
				Scope:          e.Scope,
				Recommendation: "Assign the role to a security group and add the user to it; enables access reviews and PIM.",
			})
		}

		if strings.Contains(e.PrincipalName, "#EXT#") {
			sev := "MEDIUM"
			if isPriv {
				sev = "HIGH"
			}
			findings = append(findings, Finding{
				Severity:       sev,
				Title:          "Guest (external) account with role assignment",
				Principal:      e.PrincipalName,
				PrincipalType:  e.PrincipalType,
				Role:           e.RoleName,
				Scope:          e.Scope,
				Recommendation: "Review guest necessity; restrict via Conditional Access and remove write roles if not required.",
			})
		}
	}

	SortBySeverity(findings)
	return findings
}

const (
	StaleAccountDays   = 90 // días sin sign-in para considerar "stale"
	ExpiringSecretDays = 30 // días antes de expiración para warning
)

// / EvaluateAdvanced aplica reglas que requieren consultas adicionales a Graph.
func EvaluateAdvanced(entries []Entry, graphClient *graph.Client) []Finding {
	var findings []Finding
	ctx := context.Background()

	debug := true // ← ponlo en false cuando todo funcione

	for _, e := range entries {
		/*baseSev, isPriv := privilegedRoles[e.RoleName]

		// Regla: Stale privileged account
		if isPriv && e.PrincipalType == "User" {
			lastSignIn, err := graphClient.GetSignInActivity(ctx, e.PrincipalID)
			if err != nil {
				if debug {
					fmt.Printf("   [DEBUG] signInActivity error para %s: %v\n", e.PrincipalName, err)
				}
			} else {
				if lastSignIn == nil {
					findings = append(findings, Finding{
						Severity:       "HIGH",
						Title:          "Stale privileged account (never signed in)",
						Principal:      e.PrincipalName,
						PrincipalType:  e.PrincipalType,
						Role:           e.RoleName,
						Scope:          e.Scope,
						Recommendation: "Disable account or remove role assignment; investigate if account is still needed.",
					})
				} else if time.Since(*lastSignIn) > StaleAccountDays*24*time.Hour {
					days := int(time.Since(*lastSignIn).Hours() / 24)
					findings = append(findings, Finding{
						Severity:       "HIGH",
						Title:          fmt.Sprintf("Stale privileged account (last sign-in: %d days ago)", days),
						Principal:      e.PrincipalName,
						PrincipalType:  e.PrincipalType,
						Role:           e.RoleName,
						Scope:          e.Scope,
						Recommendation: "Disable account or remove role assignment; contact user to confirm necessity.",
					})
				}
			}
		}*/

		// Regla: Service principal with expiring/expired secret
		if e.PrincipalType == "ServicePrincipal" {
			secrets, err := graphClient.GetServicePrincipalSecrets(ctx, e.PrincipalID)
			if err != nil {
				if debug {
					fmt.Printf("   [DEBUG] passwordCredentials error para %s: %v\n", e.PrincipalName, err)
				}
			} else if len(secrets) > 0 {
				for _, secret := range secrets {
					daysUntilExpiry := int(time.Until(secret.EndDateTime).Hours() / 24)

					if daysUntilExpiry < 0 {
						findings = append(findings, Finding{
							Severity:       "CRITICAL",
							Title:          fmt.Sprintf("Expired service principal secret (expired %d days ago)", -daysUntilExpiry),
							Principal:      e.PrincipalName,
							PrincipalType:  e.PrincipalType,
							Role:           e.RoleName,
							Scope:          e.Scope,
							Recommendation: "Rotate secret immediately; consider migrating to certificate-based auth or managed identity.",
						})
					} else if daysUntilExpiry <= ExpiringSecretDays {
						findings = append(findings, Finding{
							Severity:       "HIGH",
							Title:          fmt.Sprintf("Service principal secret expiring soon (in %d days)", daysUntilExpiry),
							Principal:      e.PrincipalName,
							PrincipalType:  e.PrincipalType,
							Role:           e.RoleName,
							Scope:          e.Scope,
							Recommendation: "Plan secret rotation; automate renewal via Key Vault or switch to certificate auth.",
						})
					}
				}
			}
		}
		/*
			// Regla: Privileged user without MFA
			if isPriv && e.PrincipalType == "User" {
				hasMFA, err := graphClient.GetMFAStatus(ctx, e.PrincipalID)
				if err != nil {
					if debug {
						fmt.Printf("   [DEBUG] MFA status error para %s: %v\n", e.PrincipalName, err)
					}
				} else if !hasMFA {
					severity := "CRITICAL"
					if baseSev == "HIGH" {
						severity = "HIGH"
					}
					findings = append(findings, Finding{
						Severity:       severity,
						Title:          "Privileged user without MFA registered",
						Principal:      e.PrincipalName,
						PrincipalType:  e.PrincipalType,
						Role:           e.RoleName,
						Scope:          e.Scope,
						Recommendation: "Enforce MFA registration via Conditional Access policy; block access until MFA is configured.",
					})
				}
			}*/
	}

	return findings
}
func SortBySeverity(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		return severityOrder[findings[i].Severity] < severityOrder[findings[j].Severity]
	})
}
