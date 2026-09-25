# AzRBAC-Auditor-

**Azure RBAC Posture Auditor** — CLI tool written in Go that audits identity and access management (IAM) configurations in Azure subscriptions, detecting privilege creep and security misconfigurations.

## What it does

AzRBAC Auditor connects to your Azure tenant via OAuth2 client credentials and:

- Enumerates all role assignments across the subscription
- Resolves GUIDs to human-readable names (users, groups, service principals) using Microsoft Graph API
- Detects security issues:
  - 🔴 **Critical**: Privileged roles (Owner, User Access Administrator) assigned at subscription level
  - 🟠 **High**: Roles assigned directly to users instead of groups, guest accounts with permissions
  - 🟡 **Medium**: Service principals with secrets expiring soon
- Generates executive reports in **HTML** (color-coded severity badges) and **JSON** (structured data)

## Why I built this

As a Cloud Security Engineer, I noticed that manual RBAC reviews were time-consuming and error-prone. Existing tools either required expensive licenses or lacked the specific detections I needed. AzRBAC Auditor fills that gap: a lightweight, open-source tool that runs in seconds and produces actionable findings aligned with Azure security best practices.

## Tech stack

- **Go** (concurrency, Azure SDK, Microsoft Graph REST API)
- **OAuth2 Client Credentials Flow** (service principal authentication)
- **Azure Resource Manager** (role assignments API)
- **Microsoft Graph** (identity resolution)
- **html/template** (professional HTML reports)

## Example output
