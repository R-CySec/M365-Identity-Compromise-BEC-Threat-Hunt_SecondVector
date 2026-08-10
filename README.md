# M365-Identity-Compromise-BEC-Threat-Hunt_SecondVector


**Title:** Second Vector Threat Hunt: M365 Identity Compromise & Business Email Compromise\
**Date:** 2026-08-09\
**Environment:** Microsoft Defender XDR, Microsoft Sentinel, Microsoft 365 / Entra ID\
**Source:** Log(N) Pacific Cyber Range - Hunt 08\
**Incident:** Microsoft XDR Incident 87241\

## Overview

**Objective:** Investigate a simulated Microsoft Entra incident and determine whether an initially low-risk anonymous IP address sign-in represented a broader compromise and Business Email Compromise (BEC) campaign.

**Environment:** Microsoft Defender XDR, Microsoft Sentinel, Microsoft 365 / Microsoft Entra ID

**Data Sources:**
- `SigninLogs`
- `OfficeActivity`
- `MicrosoftGraphActivityLogs`
- `EmailEvents`
- `CloudAppEvents`
- `AuditLogs`
- `IdentityLogonEvents`
- `BehaviorAnalytics`

**Tools:** KQL, Microsoft Sentinel, Microsoft Defender XDR, Microsoft 365 / Entra ID

**Scenario:**  
This investigation was conducted as part of the Log(N) Pacific Cyber Range. The investigation began with an XDR incident that had initially been rated Low by a previous SOC shift. The objective was to determine whether that assessment accurately reflected the scope of the activity and identify what the adversary accomplished after gaining access.

---

# Investigation Scope

The investigation focused on four primary intelligence gaps:

1. Determine whether the Low severity assessment accurately reflected the incident.
2. Identify what the adversary did after gaining access and what information they accessed or collected.
3. Determine whether persistence or continued access mechanisms were established.
4. Identify whether additional users were targeted or drawn into the activity.

---

# Investigation

## 1. Initial Authentication & Identity Risk

The investigation began by reviewing the Defender XDR incident and identifying the affected user's User Principal Name (UPN).

`AADUserRiskEvents` was used to examine identity risk activity and establish context around the suspicious authentication.

```kql
AADUserRiskEvents
| sort by TimeGenerated desc
