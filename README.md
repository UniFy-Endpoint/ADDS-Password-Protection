# Active Directory Password Protection & Microsoft Entra Password Protection

## A Layered Security Implementation Guide

> **Scope:** This guide provides step-by-step PowerShell commands and configuration instructions for hardening Active Directory password policies and deploying Microsoft Entra Password Protection in a hybrid environment. It follows **Microsoft Best Practices** and **CIS Benchmarks (v2.0.0)**.

| Requirement | Value |
|---|---|
| AD Functional Level | Windows Server 2016 or newer |
| Entra Connect | Azure AD Connect V2 |
| Entra ID License | P1 (minimum) or P2 |
| Deployment Mode | Audit → Enforce |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        MICROSOFT ENTRA ID                          │
│  ┌──────────────────────┐  ┌──────────────────────────────────┐    │
│  │  Global Banned        │  │  Custom Banned Password List     │    │
│  │  Password List        │  │  (Organization-Specific Terms)   │    │
│  │  (Microsoft-Managed)  │  │  (Up to 1000 entries)            │    │
│  └──────────┬───────────┘  └──────────────┬───────────────────┘    │
│             │          Password Policy     │                        │
│             └──────────┬──────────────────┘                        │
│                        │ HTTPS (443)                                │
│  ┌─────────────────────┼──────────────────────────────────────┐    │
│  │  Password Hash Sync  │  Password Writeback (SSPR)          │    │
│  │  ◄──────────────────►│◄────────────────────────────────►   │    │
│  └─────────────────────┼──────────────────────────────────────┘    │
└────────────────────────┼───────────────────────────────────────────┘
                         │
            ┌────────────┼────────────────────┐
            │   ON-PREMISES NETWORK           │
            │                                 │
            │   ┌─────────────────────┐       │
            │   │  Entra Password     │       │
            │   │  Protection Proxy   │       │
            │   │  (2+ Servers, HA)   │       │
            │   └────────┬────────────┘       │
            │            │ RPC                │
            │   ┌────────┼────────────┐       │
            │   │        ▼            │       │
            │   │  ┌───────────┐      │       │
            │   │  │  DC Agent │      │       │
            │   │  └─────┬─────┘      │       │
            │   │        ▼            │       │
            │   │  Domain Controller  │       │
            │   └─────────────────────┘       │
            │                                 │
            │   ┌─────────────────────────┐   │
            │   │  LAYER 3: Entra PP      │   │
            │   │  Banned Password Lists  │   │
            │   ├─────────────────────────┤   │
            │   │  LAYER 2: FGPP          │   │
            │   │  (Admins/SAs/VIPs)      │   │
            │   ├─────────────────────────┤   │
            │   │  LAYER 1: Default       │   │
            │   │  Domain Password Policy │   │
            │   └─────────────────────────┘   │
            │                                 │
            │   ┌─────────────────────────┐   │
            │   │  Entra Connect Sync     │   │
            │   │  (PHS + Writeback)      │   │
            │   └─────────────────────────┘   │
            └─────────────────────────────────┘
```

**Layer 1 — Default Domain Password Policy:** Baseline floor for all domain users (CIS-aligned).
**Layer 2 — Fine-Grained Password Policies (FGPP):** Stricter policies for Domain Admins, Service Accounts, and VIPs.
**Layer 3 — Entra Password Protection:** Cloud-powered banned password intelligence applied at the DC level.
**Connector — Entra Connect Sync:** Password Hash Sync (PHS) and Password Writeback bridge the on-prem and cloud worlds.

---

## Table of Contents

- [1. Global Prerequisites](#1-global-prerequisites)
- [2. Default Domain Password Policy (Baseline)](#2-default-domain-password-policy-baseline)
- [3. Account Lockout Policy](#3-account-lockout-policy)
- [4. Fine-Grained Password Policies (FGPP)](#4-fine-grained-password-policies-fgpp)
- [5. Microsoft Entra Password Protection — Proxy Service](#5-microsoft-entra-password-protection--proxy-service)
- [6. Microsoft Entra Password Protection — DC Agent](#6-microsoft-entra-password-protection--dc-agent)
- [7. Banned Password Lists Configuration](#7-banned-password-lists-configuration)
- [8. Entra Connect Sync (Azure AD Connect V2)](#8-entra-connect-sync-azure-ad-connect-v2)
- [9. User Impact — When Do Policies Take Effect?](#9-user-impact--when-do-policies-take-effect)
- [10. End-to-End Validation](#10-end-to-end-validation)
- [11. Troubleshooting Reference](#11-troubleshooting-reference)
- [12. Best Practices Summary Checklist](#12-best-practices-summary-checklist)
- [13. References](#13-references)

---

## 1. Global Prerequisites

### 1.1 Server Placement Summary

Before starting, understand where each component must be installed:

| Component | Install On | Can Co-locate? | Quantity |
|---|---|---|---|
| Entra PP Proxy Service | Member server (NOT a DC) | Yes — can share with Entra Connect Sync server* | 2+ recommended (HA) |
| Entra PP DC Agent | **Domain Controllers ONLY** | N/A — must be on every DC | All DCs in domain |
| Entra Connect Sync | Dedicated member server | Yes — can share with Entra PP Proxy* | 1 (+ optional staging) |

> **\*Co-location guidance:** If you do not have a dedicated server available for the Entra Password Protection Proxy Service, you **can** install it on the same server as Entra Connect Sync. Microsoft does not prohibit this — the Proxy is a lightweight service with minimal resource usage. However, for production environments with 5,000+ users, dedicated servers are recommended to isolate failure domains and simplify troubleshooting.
>
> **What you CANNOT do:**
> - Install the Proxy Service on a Domain Controller — this is **not supported** by Microsoft.
> - Install the DC Agent on a member server — it **only works on Domain Controllers**. The DC Agent installs a password filter DLL (`AzureADPasswordProtectionDCAgent.dll`) that hooks into the DC's `LSA` (Local Security Authority) password filter pipeline. This pipeline only exists on DCs, as they are the only servers that process password change and reset operations in Active Directory.
> - Skip installing the DC Agent on any DC — password changes processed by a DC without the agent will **bypass** the banned password list entirely.

### 1.2 Active Directory Requirements

| Requirement | Minimum |
|---|---|
| Forest Functional Level | Windows Server 2016 |
| Domain Functional Level | Windows Server 2016 |
| Writable DCs per site | At least 1 (for DC Agent) |

```powershell
# Verify Forest Functional Level
Get-ADForest | Select-Object ForestMode

# Verify Domain Functional Level and FSMO Roles
Get-ADDomain | Select-Object DomainMode, PDCEmulator, InfrastructureMaster

# List all Domain Controllers
Get-ADDomainController -Filter * | Select-Object Name, OperatingSystem, Site, IsGlobalCatalog |
    Format-Table -AutoSize
```

### 1.3 Network and Firewall Requirements

The Entra Password Protection Proxy servers require outbound HTTPS to Azure. DC Agents communicate with Proxy servers over RPC.

| Source | Destination | Port | Protocol | Purpose |
|---|---|---|---|---|
| Proxy Server | `enterpriseregistration.windows.net` | 443 | HTTPS | Proxy registration |
| Proxy Server | `login.microsoftonline.com` | 443 | HTTPS | Authentication |
| Proxy Server | `passwordreset.microsoftonline.com` | 443 | HTTPS | Password Writeback |
| DC Agent | Proxy Server | 135 + Dynamic RPC | TCP | Policy download |

```powershell
# Test outbound connectivity from Proxy servers
Test-NetConnection -ComputerName enterpriseregistration.windows.net -Port 443
Test-NetConnection -ComputerName login.microsoftonline.com -Port 443

# Verify TLS 1.2 is enabled (required)
[Net.ServicePointManager]::SecurityProtocol
# Should include "Tls12". If not, enable it:
# [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
```

### 1.4 Required PowerShell Modules

| Module | Installed With | Used For |
|---|---|---|
| `ActiveDirectory` | RSAT (Remote Server Administration Tools) | AD password policy and FGPP management |
| `AzureADPasswordProtectionProxy` | Entra PP Proxy installer | Proxy registration and health checks |
| `AzureADPasswordProtection` | Entra PP DC Agent installer | DC Agent management |
| `ADSync` | Azure AD Connect installer | Sync configuration |

```powershell
# Verify ActiveDirectory module is available
Get-Module -ListAvailable ActiveDirectory

# If not installed, add the RSAT feature
Install-WindowsFeature -Name RSAT-AD-PowerShell
```

### 1.5 Account and Permission Requirements

| Task | Required Role |
|---|---|
| AD Password Policy / FGPP changes | Domain Admins |
| Entra PP Proxy registration | Global Administrator or Security Administrator (Entra) |
| Entra PP configuration (portal) | Global Administrator or Security Administrator (Entra) |
| Entra Connect installation/upgrade | Enterprise Admin (AD) + Global Administrator (Entra) |
| Password Writeback configuration | Hybrid Identity Administrator (Entra) |

### 1.6 Licensing Requirements

| Feature | License Required |
|---|---|
| Global Banned Password List | Any Entra ID edition (including Free) |
| Custom Banned Password List | Entra ID P1 or P2 |
| Password Hash Sync (PHS) | Any Entra ID edition |
| Password Writeback (SSPR) | Entra ID P1 or P2 |

---

## 2. Default Domain Password Policy (Baseline)

The Default Domain Password Policy is the baseline floor that applies to **all domain users** unless overridden by a Fine-Grained Password Policy (FGPP). This policy is configured through the Default Domain Policy GPO and applies domain-wide.

### 2.1 Security Baseline Alignment — CIS vs. Microsoft

| Setting | CIS Recommendation | CIS Reference | Microsoft Recommendation | Microsoft Reference |
|---|---|---|---|---|
| Minimum Password Length | >= 14 characters | CIS 1.1.4 | >= 14 characters | MS Security Baseline |
| Password History Count | >= 24 passwords | CIS 1.1.1 | 24 passwords | MS Security Baseline |
| Maximum Password Age | <= 365 days | CIS 1.1.2 | No expiration* (or <= 365 days) | MSFT-PW-GUIDANCE |
| Minimum Password Age | >= 1 day | CIS 1.1.3 | 1 day | MS Security Baseline |
| Password Complexity | Enabled | CIS 1.1.5 | Enabled | MS Security Baseline |
| Reversible Encryption | Disabled | CIS 1.1.6 | Disabled | MS Security Baseline |

> **\*Microsoft Guidance on Password Expiration:** Microsoft's modern guidance (aligned with NIST SP 800-63B) recommends **removing periodic password expiration** when combined with Entra Password Protection (banned password lists), MFA, and risk-based detection. The rationale is that forced expiration leads to predictable password patterns (e.g., `Summer2025!` → `Fall2025!`). However, if your organization has not yet deployed MFA and Entra Password Protection, keeping `MaxPasswordAge <= 365 days` remains a safe default. This guide uses 365 days as a balanced approach.
>
> **Reference:** [Microsoft Password Policy Recommendations](https://learn.microsoft.com/en-us/microsoft-365/admin/misc/password-policy-recommendations)

### 2.2 Audit Current Configuration

```powershell
# Review the current Default Domain Password Policy
Get-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName |
    Select-Object ComplexityEnabled,
                  LockoutDuration,
                  LockoutObservationWindow,
                  LockoutThreshold,
                  MaxPasswordAge,
                  MinPasswordAge,
                  MinPasswordLength,
                  PasswordHistoryCount,
                  ReversibleEncryptionEnabled |
    Format-List
```

### 2.3 Configure Baseline Password Policy

```powershell
# Set the Default Domain Password Policy to CIS-aligned values
Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName `
    -ComplexityEnabled $true `
    -MinPasswordLength 14 `
    -PasswordHistoryCount 24 `
    -MaxPasswordAge "365.00:00:00" `
    -MinPasswordAge "1.00:00:00" `
    -ReversibleEncryptionEnabled $false
```

> **Note:** The Default Domain Password Policy can only be set on the Default Domain Policy GPO linked to the domain root. Do **not** create a separate GPO for these settings — they will be ignored.

### 2.4 Verification

```powershell
# Verify the policy was applied correctly
Get-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName |
    Select-Object ComplexityEnabled, MinPasswordLength, PasswordHistoryCount,
                  MaxPasswordAge, MinPasswordAge, ReversibleEncryptionEnabled |
    Format-List

# Generate a GPO report to confirm application
gpresult /h C:\Temp\GPReport.html
# Open C:\Temp\GPReport.html and verify the password policy settings under
# "Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies"

# Quick cross-check via net accounts
net accounts
```

> **Troubleshooting:** If the policy does not apply, check `gpresult /r` for conflicting GPOs with higher precedence. Look for Event ID **1101** (source: SceCli) in the Application log — this confirms successful policy application.

---

## 3. Account Lockout Policy

The Account Lockout Policy is part of the Default Domain Password Policy and protects against brute-force attacks.

### 3.1 Security Baseline Alignment — CIS vs. Microsoft

| Setting | CIS Recommendation | CIS Reference | Microsoft Recommendation | Microsoft Reference |
|---|---|---|---|---|
| Account Lockout Threshold | 1-5 attempts | CIS 1.2.2 | 10 attempts | MS Security Baseline |
| Account Lockout Duration | >= 15 minutes | CIS 1.2.1 | 15 minutes | MS Security Baseline |
| Reset Lockout Counter After | >= 15 minutes | CIS 1.2.3 | 15 minutes | MS Security Baseline |

> **Key Difference — Lockout Threshold:** CIS recommends a strict threshold of 1-5 attempts, while the Microsoft Security Baseline sets it at **10 attempts**. Microsoft's higher threshold reduces helpdesk lockout calls and account denial-of-service risk, especially in environments with MFA enabled. This guide uses **5 attempts** as a balanced middle ground. Organizations with MFA deployed broadly may consider increasing to 10 per Microsoft's guidance.

### 3.2 Configure Account Lockout Policy

```powershell
# Set the Account Lockout Policy
Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName `
    -LockoutThreshold 5 `
    -LockoutDuration "00:15:00" `
    -LockoutObservationWindow "00:15:00"
```

> **Important:** `LockoutObservationWindow` must be less than or equal to `LockoutDuration`. If you set a longer observation window than the lockout duration, the command will fail.

### 3.3 Verification

```powershell
# Verify lockout settings
Get-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName |
    Select-Object LockoutThreshold, LockoutDuration, LockoutObservationWindow |
    Format-List

# Quick cross-check
net accounts

# Test: Find currently locked-out accounts
Search-ADAccount -LockedOut | Select-Object Name, SamAccountName, LockedOut |
    Format-Table -AutoSize
```

> **Troubleshooting:**
> - **Event ID 4740** (Security log): Account was locked out — shows the source computer that triggered the lockout.
> - **Event ID 4767** (Security log): A user account was unlocked.
> - Use `Unlock-ADAccount -Identity <username>` to manually unlock an account.

---

## 4. Fine-Grained Password Policies (FGPP)

Fine-Grained Password Policies allow you to apply **different password and lockout policies** to specific users or groups within the same domain. FGPPs override the Default Domain Password Policy for targeted users.

### 4.1 How FGPP Precedence Works

| Priority | Precedence Value | Policy | Min Password Length | Target |
|---|---|---|---|---|
| Highest | 10 | FGPP-High-Privileged-Admins | 20 characters | All Tier 0 Admin groups |
| Medium | 20 | FGPP-ServiceAccounts | 30 characters | Service Account group |
| Lower | 30 | FGPP-VIPs | 16 characters | VIP/Executive group |
| Baseline | N/A | Default Domain Policy | 14 characters | All other users |

**Key rules:**
- A **lower precedence number** means **higher priority**.
- FGPPs can only be applied to **users** or **global security groups** — NOT to OUs.
- If a user is a member of multiple groups with different FGPPs, the FGPP with the **lowest precedence value** wins.
- Gaps in precedence numbering (10, 20, 30) allow inserting future policies without renumbering.

### 4.2 Create Security Groups

```powershell
# Domain Admins group already exists. Create groups for Service Accounts and VIPs.
# Adjust the -Path parameter to match your OU structure.

New-ADGroup -Name "SVC-PasswordPolicy-ServiceAccounts" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path "OU=Security Groups,DC=contoso,DC=com" `
    -Description "Members receive the Service Accounts Fine-Grained Password Policy"

New-ADGroup -Name "SVC-PasswordPolicy-VIPs" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path "OU=Security Groups,DC=contoso,DC=com" `
    -Description "Members receive the VIP Fine-Grained Password Policy"
```

### 4.3 FGPP for Tier 0 Administrators (Precedence 10)

The strictest policy — applies to **all Tier 0 privileged groups**. These are the built-in AD groups whose members have the highest level of access and are the most critical to protect.

**Tier 0 groups covered by this FGPP:**
| Group | Why It's Tier 0 |
|---|---|
| Domain Admins | Full control over all objects in the domain |
| Enterprise Admins | Full control across the entire AD forest |
| Schema Admins | Can modify the AD schema (irreversible changes) |
| Account Operators | Can create, modify, and delete user accounts and groups |
| Backup Operators | Can back up and restore files on DCs, bypass file security |
| Server Operators | Can log on to DCs, manage services, and manage shared resources |
| Print Operators | Can log on to DCs and manage printers |
| Administrators (built-in) | Full administrative access to DCs |

```powershell
# Create the Tier 0 Admins FGPP
New-ADFineGrainedPasswordPolicy -Name "FGPP-High-Privileged-Admins" `
    -DisplayName "FGPP - Tier 0 Administrators" `
    -Description "Strict password policy for all Tier 0 privileged administrator groups" `
    -Precedence 10 `
    -ComplexityEnabled $true `
    -MinPasswordLength 20 `
    -PasswordHistoryCount 24 `
    -MaxPasswordAge "180.00:00:00" `
    -MinPasswordAge "1.00:00:00" `
    -LockoutThreshold 3 `
    -LockoutDuration "00:15:00" `
    -LockoutObservationWindow "00:15:00" `
    -ReversibleEncryptionEnabled $false

# Apply the FGPP to ALL Tier 0 privileged groups
# These are built-in groups — no need to create them
Add-ADFineGrainedPasswordPolicySubject -Identity "FGPP-High-Privileged-Admins" `
    -Subjects "Domain Admins",
              "Enterprise Admins",
              "Schema Admins",
              "Account Operators",
              "Backup Operators",
              "Server Operators",
              "Print Operators",
              "Administrators"
```

> **Note:** All groups listed above are **built-in AD groups** that already exist in every Active Directory domain. You do not need to create them. Any user who is a direct member of any of these groups will automatically receive the FGPP-High-Privileged-Admins policy.

### 4.4 FGPP for Service Accounts (Precedence 20)

Service accounts use very long passwords and should **not** lock out (lockout causes service outages).

```powershell
# Create the Service Accounts FGPP
New-ADFineGrainedPasswordPolicy -Name "FGPP-ServiceAccounts" `
    -DisplayName "FGPP - Service Accounts" `
    -Description "Password policy for Service Accounts - long passwords, no lockout" `
    -Precedence 20 `
    -ComplexityEnabled $true `
    -MinPasswordLength 30 `
    -PasswordHistoryCount 24 `
    -MaxPasswordAge "365.00:00:00" `
    -MinPasswordAge "1.00:00:00" `
    -LockoutThreshold 0 `
    -LockoutDuration "00:00:00" `
    -LockoutObservationWindow "00:00:00" `
    -ReversibleEncryptionEnabled $false

# Apply the FGPP to the Service Accounts group
Add-ADFineGrainedPasswordPolicySubject -Identity "FGPP-ServiceAccounts" `
    -Subjects "SVC-PasswordPolicy-ServiceAccounts"
```

> **Recommendation:** For service accounts, consider migrating to **Group Managed Service Accounts (gMSA)** which automatically manage password rotation. gMSAs use 240-character randomly generated passwords rotated every 30 days, eliminating the need for manual password management entirely.

### 4.5 FGPP for VIPs / Executives (Precedence 30)

A moderately stricter policy for high-profile users whose accounts are high-value targets due to their visibility, access to sensitive data, or organizational authority — even though they are not IT administrators.

**Who should be in the VIPs group:**
| Role | Reason |
|---|---|
| C-Suite (CEO, CFO, CTO, COO, CISO) | Highest-value targets for spear-phishing and impersonation |
| Board Members (with domain accounts) | Access to strategic and confidential information |
| VPs and Directors | Access to sensitive financial, legal, or strategic data |
| Executive Assistants | Often have delegated access to executive mailboxes and calendars |
| Finance / Treasury Staff | Prime targets for Business Email Compromise (BEC) attacks |
| HR Leadership | Access to PII, salary data, and employee records |
| Legal Counsel | Access to privileged and confidential communications |

> **Why a separate policy?** These users are prime targets for credential stuffing, social engineering, and spear-phishing. The FGPP-VIPs policy (16-character minimum, 180-day expiry) provides stronger protection than the baseline without imposing the admin-tier strictness that could impact their daily workflow.

```powershell
# Create the VIPs FGPP
New-ADFineGrainedPasswordPolicy -Name "FGPP-VIPs" `
    -DisplayName "FGPP - VIPs" `
    -Description "Enhanced password policy for VIP and Executive accounts" `
    -Precedence 30 `
    -ComplexityEnabled $true `
    -MinPasswordLength 16 `
    -PasswordHistoryCount 24 `
    -MaxPasswordAge "180.00:00:00" `
    -MinPasswordAge "1.00:00:00" `
    -LockoutThreshold 5 `
    -LockoutDuration "00:15:00" `
    -LockoutObservationWindow "00:15:00" `
    -ReversibleEncryptionEnabled $false

# Apply the FGPP to the VIPs group
Add-ADFineGrainedPasswordPolicySubject -Identity "FGPP-VIPs" `
    -Subjects "SVC-PasswordPolicy-VIPs"
```

### 4.6 Verification

```powershell
# List all Fine-Grained Password Policies
Get-ADFineGrainedPasswordPolicy -Filter * |
    Select-Object Name, Precedence, MinPasswordLength, MaxPasswordAge, LockoutThreshold |
    Format-Table -AutoSize

# Verify which groups/users are linked to each FGPP
Get-ADFineGrainedPasswordPolicySubject -Identity "FGPP-High-Privileged-Admins"
Get-ADFineGrainedPasswordPolicySubject -Identity "FGPP-ServiceAccounts"
Get-ADFineGrainedPasswordPolicySubject -Identity "FGPP-VIPs"

# Check the resultant password policy for a specific user
# (Returns the FGPP that applies, or nothing if the Default Domain Policy applies)
Get-ADUserResultantPasswordPolicy -Identity "admin.john"
```

> **Troubleshooting:**
> - If `Get-ADUserResultantPasswordPolicy` returns nothing, the user is governed by the Default Domain Password Policy.
> - **Common mistake:** Applying an FGPP to an OU instead of a group — this silently does nothing. FGPPs must be applied to global security groups or individual user objects.
> - If a user belongs to multiple groups with different FGPPs, run `Get-ADUserResultantPasswordPolicy` to see which one actually applies (lowest precedence number wins).

---

## 5. Microsoft Entra Password Protection — Proxy Service

The Entra Password Protection Proxy Service acts as a bridge between on-premises DC Agents and the Entra cloud service. It downloads the banned password policy from Azure and makes it available to DC Agents.

### 5.1 Prerequisites

| Requirement | Details |
|---|---|
| Operating System | Windows Server 2016 or later |
| Server Role | **Member server** (do NOT install on a Domain Controller) |
| .NET Framework | 4.7.2 or later |
| Network | Outbound HTTPS (443) to Azure endpoints |
| High Availability | Minimum **2 proxy servers** recommended |
| Co-location | Can be installed on the **Entra Connect Sync server** if no dedicated server is available (see [Section 1.1](#11-server-placement-summary)) |

```powershell
# Verify .NET Framework version
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release
# Value >= 461808 means .NET 4.7.2 or later

# Verify outbound connectivity
Test-NetConnection -ComputerName enterpriseregistration.windows.net -Port 443
Test-NetConnection -ComputerName login.microsoftonline.com -Port 443
```

### 5.2 Install the Proxy Service

Download `AzureADPasswordProtectionProxySetup.exe` from the [Microsoft Download Center](https://www.microsoft.com/download).

```powershell
# Silent installation
.\AzureADPasswordProtectionProxySetup.exe /quiet

# Verify the service is installed and running
Get-Service AzureADPasswordProtectionProxy | Select-Object Name, Status, StartType
```

### 5.3 Register the Proxy with Entra ID

```powershell
# Import the module
Import-Module AzureADPasswordProtectionProxy

# Register the Proxy - this prompts for Global Admin or Security Admin credentials
Register-AzureADPasswordProtectionProxy -AccountUpn "globaladmin@contoso.onmicrosoft.com"
```

> **Note:** Registration only needs to be done once per proxy server. The proxy will automatically renew its registration.

### 5.4 Verification

```powershell
# Verify proxy registration
Get-AzureADPasswordProtectionProxy | Select-Object *

# Run a comprehensive health check
Test-AzureADPasswordProtectionProxyHealth -TestAll
```

> **Troubleshooting Event IDs** (Log: `Microsoft-AzureADPasswordProtection-Proxy/Admin`):
> | Event ID | Description |
> |---|---|
> | 20000 | Proxy service started successfully |
> | 20001 | Proxy registered successfully with Entra ID |
> | 20003 | Proxy failed to download password policy from Azure (check network) |
> | 20006 | Proxy re-registered with Entra ID |

### 5.5 Repeat for Additional Proxy Servers

Install and register the Proxy Service on at least one additional server for high availability. DC Agents will automatically discover all available proxies in the forest.

---

## 6. Microsoft Entra Password Protection — DC Agent

The DC Agent installs a password filter DLL on each Domain Controller that intercepts password change and reset operations and evaluates them against the Entra banned password list.

### 6.1 Prerequisites

| Requirement | Details |
|---|---|
| Server Role | **Domain Controllers ONLY** — cannot be installed on member servers. The agent hooks into the DC's LSA password filter pipeline, which only exists on DCs. |
| Operating System | Windows Server 2016 or later (on the DC) |
| Coverage | Must be installed on **every DC** in the domain — any DC without the agent will **bypass** the banned password list |
| Proxy Service | At least one registered Proxy in the same AD forest |
| Reboot | **Required** after installation (password filter DLL loads at boot) |

### 6.2 Install the DC Agent

Download `AzureADPasswordProtectionDCAgentSetup.msi` from the [Microsoft Download Center](https://www.microsoft.com/download).

```powershell
# Install on a single DC
msiexec /i "C:\Windows\Temp\AzureADPasswordProtectionDCAgentSetup.msi" /quiet

# IMPORTANT: Reboot the DC for the password filter DLL to load
# Schedule this during a maintenance window
Restart-Computer -Force
```

### 6.3 Bulk Deployment to All DCs

```powershell
# Deploy the DC Agent to all Domain Controllers via PowerShell Remoting
# Ensure the installer MSI is accessible on a network share

$InstallerPath = "\\FileServer\Share\AzureADPasswordProtectionDCAgentSetup.msi"
$DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName

foreach ($DC in $DCs) {
    Write-Host "Installing DC Agent on $DC..." -ForegroundColor Cyan

    Invoke-Command -ComputerName $DC -ScriptBlock {
        param($MSIPath)
        # Copy installer locally
        Copy-Item -Path $MSIPath -Destination "C:\Windows\Temp\AzureADPasswordProtectionDCAgentSetup.msi" -Force
        # Install silently
        Start-Process msiexec.exe -ArgumentList "/i C:\Windows\Temp\AzureADPasswordProtectionDCAgentSetup.msi /quiet" -Wait
    } -ArgumentList $InstallerPath

    Write-Host "DC Agent installed on $DC. Schedule a reboot during maintenance window." -ForegroundColor Green
}

# REMINDER: Each DC must be rebooted for the agent to become active.
# Schedule reboots in a rolling fashion to maintain domain availability.
```

### 6.4 Verification

```powershell
# Verify DC Agent registration (run on each DC or remotely)
Import-Module AzureADPasswordProtection
Get-AzureADPasswordProtectionDCAgent | Select-Object *

# Run a comprehensive health check
Test-AzureADPasswordProtectionDCAgentHealth -TestAll

# Get a summary report for a specific DC
Get-AzureADPasswordProtectionSummaryReport -DomainController "DC01.contoso.com"

# Verify the password filter DLL is loaded
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Notification Packages"
# Should include "AzureADPasswordProtectionDCAgent"
```

> **Troubleshooting Event IDs** (Log: `Microsoft-AzureADPasswordProtection-DCAgent/Admin`):
> | Event ID | Description |
> |---|---|
> | 10000 | DC Agent service started |
> | 10001 | DC Agent successfully loaded password policy from the Proxy |
> | 10014 | Password policy not yet available (agent just installed, waiting for first sync) |
> | 10015 | Proxy communication failure (check RPC connectivity) |
> | 10016 | DC Agent unable to process password validation (critical — investigate immediately) |
> | 30002 | Password **rejected** by banned password list — **Audit mode** (password still allowed) |
> | 30003 | Password **rejected** by banned password list — **Enforce mode** (password blocked) |
> | 30005 | Password **accepted** but would have been rejected in Enforce mode — **Audit mode only** |
> | 30008 | Custom banned password list is not configured |

---

## 7. Banned Password Lists Configuration

### 7.1 Access the Configuration

Navigate to the **Entra Admin Center**:

1. Go to [https://entra.microsoft.com](https://entra.microsoft.com)
2. Navigate to **Protection** > **Authentication methods** > **Password protection**

### 7.2 Global Banned Password List

The Global Banned Password List is **automatically enabled** for all Entra ID tenants:

- Maintained by Microsoft using real-world password spray telemetry
- Cannot be viewed, modified, or disabled
- Automatically applied to all password changes and resets
- **No action required** — this is always active

### 7.3 Custom Banned Password List

Configure organization-specific banned terms to prevent employees from using predictable passwords.

**In the Entra Admin Center:**

1. Set **"Enable custom banned password list"** → **Yes**
2. Add your organization-specific terms (one per line)
3. Click **Save**

**Recommended terms to include:**
- Company name and abbreviations
- Product and brand names
- Office locations and cities
- Local sports teams
- Common industry terms
- Seasonal/calendar terms (Summer2025, Winter2026, etc.)

> **Notes:**
> - Maximum **1,000 entries** in the custom list.
> - Entries are **case-insensitive** and automatically normalized.
> - The algorithm handles common character substitutions (e.g., `@` for `a`, `$` for `s`, `0` for `o`).
> - Minimum 4 characters per entry; entries shorter than 4 characters are ignored.

### 7.4 Deployment Mode: Audit → Enforce

#### Phase 1 — Audit Mode (Weeks 1-4)

1. In the Entra Admin Center, set **"Enable password protection on Windows Server Active Directory"** → **Yes**
2. Set **Mode** → **Audit**
3. Click **Save**

```powershell
# Monitor Audit mode events on each DC
# Event ID 30002: Password was rejected by the policy (audit - still allowed)
# Event ID 30005: Password was accepted but would have been rejected in Enforce mode
Get-WinEvent -LogName "Microsoft-AzureADPasswordProtection-DCAgent/Admin" |
    Where-Object { $_.Id -in @(30002, 30005) } |
    Select-Object TimeCreated, Id, Message |
    Format-Table -AutoSize -Wrap
```

Review the audit logs to understand:
- How many users would be affected by enforcement
- Which banned terms are being triggered
- Whether any false positives exist in your custom list

#### Phase 2 — Enforce Mode (After Analysis)

Once you've reviewed the audit data and communicated to end users:

1. In the Entra Admin Center, change **Mode** → **Enforced**
2. Click **Save**

```powershell
# Monitor Enforce mode events on each DC
# Event ID 30003: Password was rejected by the policy (enforced - password blocked)
Get-WinEvent -LogName "Microsoft-AzureADPasswordProtection-DCAgent/Admin" |
    Where-Object { $_.Id -eq 30003 } |
    Select-Object TimeCreated, Id, Message |
    Format-Table -AutoSize -Wrap
```

> **Important:** Send a communication to all users **before** switching to Enforce mode, explaining that passwords containing company-related terms or commonly breached passwords will no longer be accepted.

### 7.5 Verification

```powershell
# Verify the DC Agent has downloaded the latest policy
Get-AzureADPasswordProtectionDCAgent |
    Select-Object ServerFQDN, SoftwareVersion, Domain, HeartbeatUTC

# Check the last policy download timestamp (on each DC)
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\AzureADPasswordProtection\DCAgent" `
    -Name LastPolicyDownloadTime -ErrorAction SilentlyContinue
```

---

## 8. Entra Connect Sync (Azure AD Connect V2)

Azure AD Connect V2 synchronizes on-premises AD with Microsoft Entra ID. For this guide, we need **Password Hash Sync (PHS)** enabled for cloud authentication and **Password Writeback** enabled for Self-Service Password Reset (SSPR).

### 8.1 Prerequisites

| Requirement | Details |
|---|---|
| Azure AD Connect Version | V2 (V1 is end-of-life — upgrade required if still on V1) |
| .NET Framework | 4.7.2 or later |
| SQL | SQL Server Express LocalDB (default) or full SQL instance |
| Permissions | Enterprise Admin (AD) + Global Administrator (Entra) |
| License | Entra ID P1 for Password Writeback |

### 8.2 Check Current Version

```powershell
# Method 1: Registry (most reliable)
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Azure AD Connect" -Name Version |
    Select-Object Version

# Method 2: ADSync module
Import-Module ADSync
(Get-ADSyncGlobalSettings).Parameters |
    Where-Object { $_.Name -eq "Microsoft.Synchronize.ServerConfigurationVersion" } |
    Select-Object Name, Value

# Method 3: Check auto-upgrade status
Get-ADSyncAutoUpgrade
# Should return "Enabled" - if "Suspended" or "Disabled", investigate
```

> If you are running Azure AD Connect V1 (version 1.x.x.x), you **must** upgrade to V2. V1 has been retired and no longer receives security updates.

### 8.3 In-Place Upgrade

1. **Download** the latest Azure AD Connect V2 installer from the [Microsoft Download Center](https://www.microsoft.com/download).
2. **Close** the Azure AD Connect wizard if it is open.
3. **Run** the installer — it detects the existing installation and performs an in-place upgrade.

```powershell
# Run the installer (interactive - requires GUI)
Start-Process ".\AzureADConnect.msi" -Wait

# After upgrade, verify the new version
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Azure AD Connect" -Name Version |
    Select-Object Version

# Verify auto-upgrade is still enabled
Get-ADSyncAutoUpgrade

# If auto-upgrade was disabled, re-enable it
Set-ADSyncAutoUpgrade -AutoUpgradeState Enabled
```

### 8.4 Enable Password Hash Sync (PHS)

Password Hash Sync sends a hash of the on-premises password hash to Entra ID, enabling cloud authentication and leaked credential detection.

```powershell
# Check current PHS status
Import-Module ADSync
Get-ADSyncAADCompanyFeature | Select-Object PasswordHashSync

# Enable PHS (replace connector name with your AD connector)
# To find your connector name:
Get-ADSyncConnector | Select-Object Name, Type
# Look for the connector of type "AD" — e.g., "contoso.com"

# Enable Password Hash Sync on the Entra ID connector
Set-ADSyncAADPasswordHashSyncConfiguration -ConnectorName "contoso.onmicrosoft.com - AAD" -Enable $true

# Trigger an initial full sync to push password hashes
Start-ADSyncSyncCycle -PolicyType Initial
```

### 8.5 Verification — Password Hash Sync

```powershell
# Check the sync cycle status
Get-ADSyncConnectorRunStatus

# Verify PHS is enabled
Get-ADSyncAADCompanyFeature | Select-Object PasswordHashSync

# Check the sync scheduler
Get-ADSyncScheduler | Select-Object AllowedSyncCycleInterval, CurrentlyEffectiveSyncCycleInterval,
    SyncCycleEnabled, NextSyncCycleStartTimeInUTC
```

> **Verification in Entra:** After the sync completes (typically within 2-30 minutes), test by signing into an Entra-integrated application (e.g., [https://myapps.microsoft.com](https://myapps.microsoft.com)) with an on-prem user account.

### 8.6 Enable Password Writeback

Password Writeback allows users who reset their password via Entra SSPR to have the new password written back to on-premises AD.

```powershell
# Check current Password Writeback status
Get-ADSyncAADCompanyFeature | Select-Object PasswordWriteBack

# Enable Password Writeback
Set-ADSyncAADCompanyFeature -PasswordWriteBack $true

# Verify the change
Get-ADSyncAADCompanyFeature | Select-Object PasswordWriteBack
```

> **Note:** Password Writeback is typically enabled through the Azure AD Connect wizard under **Optional Features**. The PowerShell method above is an alternative. After enabling, also verify in the Entra Admin Center:
> 1. Navigate to **Protection** > **Password reset** > **On-premises integration**
> 2. Confirm **"Write back passwords to your on-premises directory"** is set to **Yes**

### 8.7 Verification — Password Writeback

```powershell
# Test connectivity to Entra for writeback
Invoke-WebRequest -Uri "https://passwordreset.microsoftonline.com" -UseBasicParsing |
    Select-Object StatusCode

# Check the ADSync service is running
Get-Service ADSync | Select-Object Name, Status, StartType
```

**End-to-end writeback test:**
1. Navigate to [https://passwordreset.microsoftonline.com](https://passwordreset.microsoftonline.com)
2. Initiate a password reset for a synced test user
3. Verify the on-prem AD password is updated by logging into a domain-joined machine with the new password
4. Check **Event ID 906** on the Entra Connect server (source: ADSync) — confirms the password change was written back

> **Troubleshooting Event IDs** (Application log, source: ADSync):
> | Event ID | Description |
> |---|---|
> | 611 | Password Hash Sync heartbeat (confirms PHS is running) |
> | 656 | Password Hash Sync extraction began for a batch |
> | 657 | Password Hash Sync extraction finished for a batch |
> | 906 | Password change request forwarded to on-premises AD (writeback success) |
> | 907 | Password change request failed (writeback failure — check permissions) |
> | 33004 | Automatic upgrade failed (investigate and upgrade manually) |

---

## 9. User Impact — When Do Policies Take Effect?

Not all settings take effect immediately. Understanding the timing is critical for setting expectations with end users and ServiceDesk teams.

### 9.1 Immediate Effect (active right after configuration)

| Setting | Scope | Impact |
|---|---|---|
| Account Lockout (5 attempts / 15 min) | All users | Users who enter wrong password 5 times will be locked out |
| FGPP Lockout — Admins (3 attempts / 15 min) | Tier 0 groups | Stricter lockout for admin accounts |
| FGPP Lockout — VIPs (5 attempts / 15 min) | VIP group | Same threshold, aligned with baseline |

### 9.2 At Next Password Change Only (NOT retroactive)

| Setting | Scope | Impact |
|---|---|---|
| Minimum Password Length (14 chars) | All users | Only enforced when setting a new password |
| Password Complexity | All users | Only enforced when setting a new password |
| Password History (24) | All users | Only checked when setting a new password |
| Entra PP Banned Password List | All users | Only evaluated during password change/reset |
| FGPP password rules (length, complexity) | Targeted groups | Only enforced when setting a new password |

### 9.3 Calculated from Last Password Change

| Setting | Scope | Impact |
|---|---|---|
| Max Password Age (365 days) | All users | Countdown starts from the user's last `PasswordLastSet` date |
| FGPP Max Password Age (180 days) | Admins / VIPs | Same — calculated from last password change |

> **Key takeaway for ServiceDesk:** Users with short or weak current passwords can continue logging in without issues. Only when they change their password (voluntarily or at expiration) will the new rules be enforced. The only immediate user-facing change is account lockout after too many failed login attempts.

```powershell
# Check when a user's password was last set and when it will expire
Get-ADUser -Identity "username" -Properties PasswordLastSet, msDS-UserPasswordExpiryTimeComputed |
    Select-Object Name, PasswordLastSet,
        @{Name="PasswordExpiry";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}}
```

---

## 10. End-to-End Validation

After completing all configuration steps, run these validation tests to confirm the entire layered stack is operational.

### 9.1 Test Default Domain Password Policy

```powershell
# Create a test user
New-ADUser -Name "Test.PasswordPolicy" -SamAccountName "test.pwpolicy" `
    -UserPrincipalName "test.pwpolicy@contoso.com" `
    -Path "OU=Test,DC=contoso,DC=com" -Enabled $true `
    -AccountPassword (ConvertTo-SecureString "C0mpl3x!P@ssw0rd#2026" -AsPlainText -Force)

# Test: Attempt to set a password that is too short (should fail)
Set-ADAccountPassword -Identity "test.pwpolicy" `
    -NewPassword (ConvertTo-SecureString "Short1!" -AsPlainText -Force) `
    -Reset
# Expected: Error - password does not meet length requirements

# Test: Attempt to set a password without complexity (should fail)
Set-ADAccountPassword -Identity "test.pwpolicy" `
    -NewPassword (ConvertTo-SecureString "simplelongpassword" -AsPlainText -Force) `
    -Reset
# Expected: Error - password does not meet complexity requirements
```

### 9.2 Test Fine-Grained Password Policy

```powershell
# Add the test user to the Domain Admins group (temporarily)
Add-ADGroupMember -Identity "Domain Admins" -Members "test.pwpolicy"

# Verify the FGPP applies
Get-ADUserResultantPasswordPolicy -Identity "test.pwpolicy"
# Expected: FGPP-High-Privileged-Admins (Precedence 10, MinPasswordLength 20)

# Test: Attempt a 15-character password (meets default but fails FGPP)
Set-ADAccountPassword -Identity "test.pwpolicy" `
    -NewPassword (ConvertTo-SecureString "C0mpl3xP@ss15!" -AsPlainText -Force) `
    -Reset
# Expected: Error - password does not meet the 20-character minimum

# Clean up: Remove test user from Domain Admins
Remove-ADGroupMember -Identity "Domain Admins" -Members "test.pwpolicy" -Confirm:$false
```

### 9.3 Test Entra Banned Password List

```powershell
# Attempt to set a password containing a banned term (e.g., your company name)
# Replace "Contoso" with your actual banned term
Set-ADAccountPassword -Identity "test.pwpolicy" `
    -NewPassword (ConvertTo-SecureString "Contoso2026!@#$" -AsPlainText -Force) `
    -Reset

# In AUDIT mode: Password is accepted, but check for Event ID 30005 on the DC
Get-WinEvent -LogName "Microsoft-AzureADPasswordProtection-DCAgent/Admin" -MaxEvents 10 |
    Where-Object { $_.Id -in @(30002, 30005) } |
    Select-Object TimeCreated, Id, Message

# In ENFORCE mode: Password is rejected, check for Event ID 30003
```

### 9.4 Test Password Hash Sync

```powershell
# Change the test user's on-prem password
Set-ADAccountPassword -Identity "test.pwpolicy" `
    -NewPassword (ConvertTo-SecureString "N3wC0mpl3x!P@ssw0rd#2026" -AsPlainText -Force) `
    -Reset

# Wait 2-5 minutes for PHS to sync
# Then verify the user can sign into https://myapps.microsoft.com with the new password

# Check sync status on the Entra Connect server
Get-ADSyncConnectorRunStatus
```

### 9.5 Test Password Writeback

1. Navigate to [https://passwordreset.microsoftonline.com](https://passwordreset.microsoftonline.com)
2. Reset the password for `test.pwpolicy@contoso.com`
3. Verify on the Domain Controller that the password was updated:

```powershell
# Check the password last set timestamp
Get-ADUser -Identity "test.pwpolicy" -Properties PasswordLastSet |
    Select-Object Name, PasswordLastSet

# Verify Event ID 906 on the Entra Connect server
Get-WinEvent -LogName Application -MaxEvents 50 |
    Where-Object { $_.ProviderName -eq "ADSync" -and $_.Id -eq 906 } |
    Select-Object TimeCreated, Id, Message
```

### 9.6 Clean Up Test User

```powershell
# Remove the test user after validation
Remove-ADUser -Identity "test.pwpolicy" -Confirm:$false
```

---

## 11. Troubleshooting Reference

### 10.1 Event ID Quick Reference

| Component | Log Location | Event ID | Meaning |
|---|---|---|---|
| AD Security | Security log | 4723 | Password change attempt |
| AD Security | Security log | 4724 | Password reset attempt |
| AD Security | Security log | 4740 | Account locked out |
| AD Security | Security log | 4767 | Account unlocked |
| AD Policy | Application log | 1101 | SceCli — policy applied successfully |
| Entra PP DC Agent | AzureADPasswordProtection-DCAgent/Admin | 10000 | DC Agent service started |
| Entra PP DC Agent | AzureADPasswordProtection-DCAgent/Admin | 10001 | Password policy loaded successfully |
| Entra PP DC Agent | AzureADPasswordProtection-DCAgent/Admin | 10014 | Policy not yet available (waiting for sync) |
| Entra PP DC Agent | AzureADPasswordProtection-DCAgent/Admin | 10015 | Proxy communication failure |
| Entra PP DC Agent | AzureADPasswordProtection-DCAgent/Admin | 10016 | Unable to process password validation (critical) |
| Entra PP DC Agent | AzureADPasswordProtection-DCAgent/Admin | 30002 | Password rejected (Audit mode — allowed) |
| Entra PP DC Agent | AzureADPasswordProtection-DCAgent/Admin | 30003 | Password rejected (Enforce mode — blocked) |
| Entra PP DC Agent | AzureADPasswordProtection-DCAgent/Admin | 30005 | Would reject in Enforce (Audit mode) |
| Entra PP DC Agent | AzureADPasswordProtection-DCAgent/Admin | 30008 | Custom banned list not configured |
| Entra PP Proxy | AzureADPasswordProtection-Proxy/Admin | 20000 | Proxy service started |
| Entra PP Proxy | AzureADPasswordProtection-Proxy/Admin | 20001 | Proxy registered with Entra ID |
| Entra PP Proxy | AzureADPasswordProtection-Proxy/Admin | 20003 | Failed to download policy from Azure |
| Entra PP Proxy | AzureADPasswordProtection-Proxy/Admin | 20006 | Proxy re-registered |
| Entra Connect | Application log (ADSync) | 611 | PHS heartbeat |
| Entra Connect | Application log (ADSync) | 656 | PHS extraction started |
| Entra Connect | Application log (ADSync) | 657 | PHS extraction finished |
| Entra Connect | Application log (ADSync) | 906 | Password writeback success |
| Entra Connect | Application log (ADSync) | 907 | Password writeback failure |
| Entra Connect | Application log (ADSync) | 33004 | Auto-upgrade failed |

### 10.2 Common Issues and Resolutions

#### DC Agent Cannot Contact the Proxy

**Symptoms:** Event ID 10015 on DC, no policy loaded.

```powershell
# Test RPC connectivity from DC to Proxy
Test-NetConnection -ComputerName ProxyServer01.contoso.com -Port 135

# Verify the Proxy service is running
Invoke-Command -ComputerName ProxyServer01 -ScriptBlock {
    Get-Service AzureADPasswordProtectionProxy | Select-Object Name, Status
}

# Verify Proxy is registered and healthy
Invoke-Command -ComputerName ProxyServer01 -ScriptBlock {
    Test-AzureADPasswordProtectionProxyHealth -TestAll
}
```

**Resolution:** Ensure firewall rules allow RPC (TCP 135 + dynamic ports 49152-65535) from all DCs to all Proxy servers.

#### Proxy Cannot Reach Azure

**Symptoms:** Event ID 20003 on Proxy server.

```powershell
# Force TLS 1.2 and test connectivity
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Invoke-WebRequest -Uri "https://enterpriseregistration.windows.net" -UseBasicParsing |
    Select-Object StatusCode

Invoke-WebRequest -Uri "https://login.microsoftonline.com" -UseBasicParsing |
    Select-Object StatusCode

# Check if a web proxy is blocking the connection
netsh winhttp show proxy
```

**Resolution:**
- Enable TLS 1.2 system-wide via registry if needed
- Configure proxy exclusions for Azure endpoints
- Verify no SSL inspection is interfering with the connection

#### FGPP Not Applying to Users

**Symptoms:** `Get-ADUserResultantPasswordPolicy` returns nothing for a user who should have an FGPP.

```powershell
# Verify the user is a member of the correct group
Get-ADPrincipalGroupMembership -Identity "username" |
    Select-Object Name | Sort-Object Name

# Verify the FGPP is linked to the correct group
Get-ADFineGrainedPasswordPolicySubject -Identity "FGPP-High-Privileged-Admins"
```

**Common causes:**
- FGPP was applied to an OU instead of a group (FGPPs ignore OUs)
- User is not a direct member of the group
- Group is not a Global Security group

#### Password Hash Sync Not Working

**Symptoms:** Users cannot authenticate to Entra with their on-prem password.

```powershell
# Check sync status
Import-Module ADSync
Get-ADSyncConnectorRunStatus

# Check for sync errors
Get-ADSyncRunStepResult -RunHistoryId (
    (Get-ADSyncRunProfileResult -NumberRequested 1).RunHistoryId
)

# Verify the AD connector account has the required permissions
# The connector account needs "Replicating Directory Changes" and
# "Replicating Directory Changes All" permissions on the domain
```

#### Password Writeback Failing

**Symptoms:** Event ID 907 on Entra Connect server, SSPR resets fail to update on-prem password.

```powershell
# Verify writeback is enabled
Get-ADSyncAADCompanyFeature | Select-Object PasswordWriteBack

# Test connectivity to the writeback endpoint
Test-NetConnection -ComputerName passwordreset.microsoftonline.com -Port 443

# Verify the AD connector account has password reset permissions
# The connector account needs "Reset Password" and "Change Password"
# permissions on user objects in AD

# Check the Entra Connect service account
Get-ADSyncConnector | Where-Object { $_.Type -eq "AD" } |
    Select-Object Name, ConnectivityParameters
```

**Resolution:** Ensure the AD connector account has the `Reset Password` and `Change Password` extended rights on user objects. Use the Azure AD Connect wizard to re-run the permissions configuration.

### 10.3 Diagnostic Commands Summary

```powershell
# ─── Entra Password Protection Proxy Health ───
Test-AzureADPasswordProtectionProxyHealth -TestAll

# ─── Entra Password Protection DC Agent Health ───
Test-AzureADPasswordProtectionDCAgentHealth -TestAll

# ─── Entra Connect Sync Status ───
Import-Module ADSync
Get-ADSyncConnectorRunStatus
Get-ADSyncScheduler

# ─── Force a sync cycle ───
Start-ADSyncSyncCycle -PolicyType Delta

# ─── Check all DC Agents across the domain ───
Get-ADDomainController -Filter * | ForEach-Object {
    Write-Host "Checking $($_.HostName)..." -ForegroundColor Cyan
    Invoke-Command -ComputerName $_.HostName -ScriptBlock {
        Import-Module AzureADPasswordProtection -ErrorAction SilentlyContinue
        Get-AzureADPasswordProtectionDCAgent -ErrorAction SilentlyContinue
    }
}

# ─── Force TLS 1.2 (run in elevated session) ───
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
```

---

## 12. Best Practices Summary Checklist

### Active Directory Password Policy

| Setting | Value | CIS | Microsoft |
|---|---|---|---|
| `MinPasswordLength` | >= 14 characters | CIS 1.1.4 | MS Baseline |
| `PasswordHistoryCount` | >= 24 passwords | CIS 1.1.1 | MS Baseline |
| `ComplexityEnabled` | True | CIS 1.1.5 | MS Baseline |
| `ReversibleEncryptionEnabled` | False | CIS 1.1.6 | MS Baseline |
| `MaxPasswordAge` | <= 365 days (or no expiry*) | CIS 1.1.2 | MSFT-PW-GUIDANCE* |
| `MinPasswordAge` | >= 1 day | CIS 1.1.3 | MS Baseline |
| `LockoutThreshold` | 5 attempts (CIS: 1-5, MS: 10) | CIS 1.2.2 | MS Baseline |
| `LockoutDuration` | >= 15 minutes | CIS 1.2.1 | MS Baseline |
| `LockoutObservationWindow` | >= 15 minutes | CIS 1.2.3 | MS Baseline |

> *\*Microsoft recommends removing password expiration when MFA + Entra Password Protection are deployed.*

- [ ] All password policy values meet or exceed the table above
- [ ] Reviewed the CIS vs. Microsoft lockout threshold difference for your environment

### Fine-Grained Password Policies

- [ ] Tier 0 Admins (Domain Admins, Enterprise Admins, Schema Admins, Account/Backup/Server/Print Operators, Administrators): `MinPasswordLength` >= 20, `Precedence` 10
- [ ] Service Accounts: `MinPasswordLength` >= 30, `Precedence` 20 (or migrated to gMSA)
- [ ] VIPs: `MinPasswordLength` >= 16, `Precedence` 30
- [ ] All FGPPs applied to **global security groups** (NOT OUs)
- [ ] `Get-ADUserResultantPasswordPolicy` verified for sample users in each group

### Entra Password Protection

- [ ] Proxy Service installed on **2+ member servers** (high availability)
- [ ] Proxy Service registered with Entra ID
- [ ] DC Agent installed on **ALL Domain Controllers**
- [ ] **All DCs rebooted** after DC Agent installation
- [ ] `Test-AzureADPasswordProtectionProxyHealth -TestAll` passes
- [ ] `Test-AzureADPasswordProtectionDCAgentHealth -TestAll` passes
- [ ] Custom banned password list **enabled** with organization-specific terms
- [ ] Deployed in **Audit mode first** and logs reviewed
- [ ] Switched to **Enforce mode** after audit analysis
- [ ] TLS 1.2 enabled on all Proxy and DC servers
- [ ] End-user communication sent before switching to Enforce mode

### Entra Connect Sync

- [ ] Running Azure AD Connect **V2** (latest version)
- [ ] `Get-ADSyncAutoUpgrade` returns **Enabled**
- [ ] **Password Hash Sync (PHS)** enabled and verified
- [ ] **Password Writeback** enabled (if SSPR is used)
- [ ] Sync errors monitored regularly via `Get-ADSyncConnectorRunStatus`

### Operational

- [ ] Monitoring configured for critical Event IDs (see Section 10.1)
- [ ] Runbook documented for Entra PP policy download failures (Event ID 20003)
- [ ] Regular review of custom banned password list (quarterly recommended)
- [ ] Maintenance window process documented for DC Agent updates/reboots
- [ ] Service account password rotation or gMSA migration tracked

---

## 13. References

| Resource | Link |
|---|---|
| Plan and deploy on-premises Microsoft Entra Password Protection | [Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-ban-bad-on-premises-deploy) |
| Fine-Grained Password Policies | [Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-#fine_grained_pswd_policy_mgmt) |
| Azure AD Connect V2 — Upgrade | [Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-upgrade-previous-version) |
| Password Hash Sync | [Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-password-hash-synchronization) |
| Password Writeback | [Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-sspr-writeback) |
| Microsoft Password Policy Recommendations | [Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/admin/misc/password-policy-recommendations) |
| Microsoft Security Baselines — Windows Server | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-guard/windows-defender-application-control/windows-security-baselines) |
| Microsoft Security Baselines — Account Lockout | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-policy) |
| Entra Password Protection Troubleshooting | [Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-ban-bad-on-premises-troubleshoot) |
| CIS Microsoft Windows Server 2022 Benchmark v2.0.0 | [CIS Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_server) |
| NIST SP 800-63B — Digital Identity Guidelines | [NIST](https://pages.nist.gov/800-63-3/sp800-63b.html) |

---

> **Document Version:** 1.0 | **Last Updated:** 2026-02-15 | **Author:** Identity Architecture Team
