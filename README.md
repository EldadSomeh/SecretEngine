# 🔐 Keymistry - Secret Rotation for Azure App Registrations <img width="520" height="232" alt="2" src="https://github.com/user-attachments/assets/d15e68fc-b686-4443-8ffb-e685ee08d379" />


**Keymistry** is a secure and automated Azure Logic App that rotates secrets (client passwords) for App Registrations (service principals) in Microsoft Entra ID. It stores the new password securely in Azure Key Vault and supports both scheduled and event-driven execution.

---

## 🚀 Features

- 🔄 Automatically rotates client secrets for Entra ID App Registrations
- 🔐 Unlocks and re-locks SPN credentials for secure credential lifecycle
- 💾 Stores new secret in Azure Key Vault with expiration metadata
- 🔔 Triggered by HTTP request, Event Grid (Key Vault near-expiry), or recurrence
- 🔐 Uses a system-assigned Managed Identity with least-privilege permissions

---

## 📋 Prerequisites

### 🔧 Azure Resources
- Azure Logic App (Consumption or Standard)
- System-assigned Managed Identity enabled on the Logic App
- Azure Key Vault with appropriate access policies
- An App Registration (Service Principal) in Entra ID

---

## 🔐 Required Permissions

### Microsoft Graph Application Permissions
These permissions must be granted to the **Enterprise Application** (Managed Identity) in Microsoft Entra ID:

| Permission Name              | Type         | Purpose                            |
|-----------------------------|--------------|------------------------------------|
| `Application.ReadWrite.All` | Application  | Required to reset (add) secrets on any app registration |
| `Directory.Read.All`        | Application  | Optional – used to search SPNs by name |

> 💡 These must be **granted admin consent** by a Global Administrator.

### Key Vault Role
Assign the following RBAC role to the Managed Identity:

- `Key Vault Secrets Officer` (scope: specific Key Vault)

```bash
az role assignment create \
  --assignee <logic-app-managed-identity-object-id> \
  --role "Key Vault Secrets Officer" \
  --scope /subscriptions/<sub-id>/resourceGroups/<rg-name>/providers/Microsoft.KeyVault/vaults/<vault-name>
```
### Assgien Permission for MSI in MS Graph
``` Powershell
<#
.SYNOPSIS
  Assigns Microsoft Graph API Application Permissions to a Managed Identity (Enterprise Application).
.DESCRIPTION
  Finds the managed identity service principal, retrieves Microsoft Graph's service principal,
  and assigns specified Graph application roles. Requires Global Administrator privileges.
.NOTES
  - Requires Microsoft.Graph and Az modules
  - Script mimics the TechCommunity blog post logic (Joyce_Dorothy, 2021)
#>

param (
  [Parameter(Mandatory)]
  [string] $TenantId,

  [Parameter(Mandatory)]
  [string] $ManagedIdentityName,  # Display name of the Managed Identity

  [Parameter()]
  [string[]] $Permissions = @(
    "Application.ReadWrite.All",
    "Directory.Read.All"
  )
)

# Install modules if missing
if (-not (Get-Module -ListAvailable Microsoft.Graph)) {
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
}
if (-not (Get-Module -ListAvailable Az.Resources)) {
    Install-Module Az.Resources -Scope CurrentUser -Force
}

# Connect to Azure and Microsoft Graph
Connect-AzAccount -TenantId $TenantId | Out-Null
Connect-MgGraph -TenantId $TenantId -Scopes "AppRoleAssignment.ReadWrite.All", `
                                          "Application.Read.All", `
                                          "Directory.Read.All" | Out-Null

# Microsoft Graph AppId
$GraphAppId = "00000003-0000-0000-c000-000000000000"

Write-Host "Retrieving enterprise application for managed identity '$ManagedIdentityName'..."
$miSp = Get-MgServicePrincipal -Filter "displayName eq '$ManagedIdentityName'"
if (-not $miSp) {
    throw "Managed Identity service principal not found: $ManagedIdentityName"
}

Write-Host "Retrieving Microsoft Graph service principal..."
$graphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'"
if (-not $graphSp) {
    throw "Microsoft Graph service principal not found"
}

foreach ($perm in $Permissions) {
    Write-Host "Assigning app role '$perm'..."

    $appRole = $graphSp.AppRoles | Where-Object {
        $_.Value -eq $perm -and $_.AllowedMemberTypes -contains "Application"
    }
    if (-not $appRole) {
        Write-Warning "Permission '$perm' not found in Graph AppRoles."
        continue
    }

    $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $miSp.Id |
        Where-Object { $_.AppRoleId -eq $appRole.Id }
    if ($existing) {
        Write-Host "Already assigned: $perm"
        continue
    }

    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $miSp.Id `
        -PrincipalId $miSp.Id `
        -ResourceId $graphSp.Id `
        -AppRoleId $appRole.Id | Out-Null

    Write-Host "Assigned: $perm"
}

Write-Host "All permissions assigned successfully."
Disconnect-MgGraph

```
