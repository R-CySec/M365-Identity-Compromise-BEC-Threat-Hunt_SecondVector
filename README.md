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

**Objective:** The investigation began by reviewing the Defender XDR incident and identifying the affected user's User Principal Name (UPN).

==**Approach:** `AADUserRiskEvents` was used to examine identity risk activity and establish context around the suspicious authentication.==

```kql
AADUserRiskEvents
| sort by TimeGenerated desc
```

**Finding:** The investigation identified suspicious authentication activity associated with the affected Microsoft 365 identity `m.smith@lognpacific.org`.
## 2. Suspicious Successful Authentication
**Approach:** `SigninLogs` was used to investigate authentication activity associated with the suspicious source IP (`103.69.224.136`) and affected user (`m.smith@lognpacific.org`).

```kql
SigninLogs
| where IPAddress contains "224.136"
| where Identity contains "Smith"
| where ResultSignature contains "success"
```

The investigation initially relied heavily on `TimeGenerated` when reconstructing authentication activity. Further investigation demonstrated that `CreatedDateTime` was more appropriate for establishing the sequence of authentication attempts in this case.

**Finding:**  The investigation identified an unauthorized successful authentication associated with the suspicious source IP. ==Note: The evidence did not indicate that the adversary hijacked an existing session, so the finding is characterized as an unauthorized successful authentication rather than session hijacking.==

## 3. Failed Authentication Attempts
**Approach:** Authentication failures were identified using Entra authentication result code `50126`. The investigation initially produced inconsistent results because the Sentinel time range excluded earlier authentication events. ==Expanding the time range to 24 hours prior to the initial Microsoft Entra ID Alert revealed two authentication failures preceding the suspicious successful authentication.==



```kql
SigninLogs
| where IPAddress contains "224.136"
| where Identity contains "Smith"
| where ResultSignature contains "failure"
| where ResultType contains "50126"
```

**Finding:** Two failed authentication attempts occurred before the successful authentication from the suspicious IP `103.69.224.136`. This established evidence of attempted unauthorized access preceding the successful authentication.

## 4. Post-Authentication Application Activity

**Approach:** The investigation examined successful authentication activity associated with the suspicious IP and user and summarized the applications accessed.

```kql
SigninLogs
| where IPAddress == "103.69.224.136"
| where UserPrincipalName =~ "m.smith@lognpacific.org"
| where ResultType == "0"
| summarize DistinctApps = dcount(AppDisplayName)
```

`SessionId` was also examined to identify related authentication activity:

```kql
SigninLogs
| where IPAddress contains "224.136"
| where Identity contains "Smith"
| where ResultSignature contains "success"
| summarize Frequency = count() by SessionId
```

**Finding:** The successful authentication was followed by activity across multiple Microsoft 365 applications, providing additional evidence that the authentication was associated with ==meaningful account activity rather than an isolated authentication event.==

## 5. Microsoft Graph Activity
**Approach:** `MicrosoftGraphActivityLogs` was used to investigate programmatic Microsoft 365 activity originating from the suspicious IP.

The investigation identified Microsoft Graph activity involving report endpoints and `$batch` requests. Additional investigation focused on Graph requests involving the affected user's resources, including `/me/` requests referencing groups or membership information.

```kql
MicrosoftGraphActivityLogs
| where IPAddress == "103.69.224.136"
| where RequestUri has "/reports/"
| project TimeGenerated, RequestUri
| order by TimeGenerated asc
```

**Finding:**  Microsoft Graph telemetry provided evidence of ==programmatic interaction with Microsoft 365 resources== following the suspicious authentication. This demonstrated the value of correlating authentication telemetry with API activity when investigating cloud identity compromise.

## 6. Internal Targeting and Business Email Compromise
**Approach:** `EmailEvents` was used to identify email activity associated with the malicious sender IP and the relevant investigation timeframe. The investigation identified an existing email conversation concerning banking information involving another organizational user.

```kql
EmailEvents
| where TimeGenerated between (datetime(2026-06-11 03:00)..datetime(2026-06-11 13:00))
| where SenderIPv4 == "103.69.224.136"
| project TimeGenerated, SenderIPv4, RecipientEmailAddress, Subject
```

A broadened timeframe and Subject keyword search showed an email Subject: `Q1 Vendor Payment Schedule - Review Required` that predates the intrusion by five months.  This email is an internal payment-approval conversation TAs tend to seek and reference during the recon phase when pricing the fraudulent payment. 

```kql
EmailEvents
| where TimeGenerated between (datetime(2026-01-01 03:00)..datetime(2026-06-11 13:00))
| where Subject contains "payment" or Subject contains "approval process"
| project TimeGenerated, Subject, SenderIPv4, RecipientEmailAddress
```


**Finding:** After gaining access to the `m.smith@lognpacific.org` account, the adversary leveraged an existing email conversation concerning banking information to target  `j.reynolds@lognpacific.org` with an illegitimate payment information email. This behavior is consistent with **MITRE ATT&CK T1534 - Internal Spearphishing**, where a compromised internal account is used to target another user within the organization.
The activity demonstrated that the compromise was not limited to the initially affected account.

==Shortly after a second channel reinforcement by the Threat Actor occurred when they pushed a second illegitimate request to update the  payment information via a Teams message. This adds to the pretext of the situation, further increasing the perspective of legitimacy to the second target,== `j.reynolds@lognpacific.org`.  

## 7. Malicious Email Forwarding and Hiding Rules
**Approach:** `CloudAppEvents` was used to investigate additional Microsoft 365 application activity. The investigation identified malicious forwarding and email-hiding activity facilitated by Power Automate. 

**Finding:** The adversary established two rules to forward email to an external Proton Mail account (`merovingian1337@proton.me`) and another rule to archive messages containing terms associated with the adversary's targeted banking information. This behavior is consistent with **MITRE ATT&CK T1564.008 - Email Hiding Rules**.

The forwarding and archiving behavior provided both persistence of access to relevant communications and a mechanism for reducing the likelihood that the activity would be noticed by the legitimate user.

## Targeted Data Collection
**Approach:** The investigation identified multiple `FileDownloaded` events and examined the associated `SourceFileName` values.
Three files were specifically targeted:
- `VPN Access Creds.txt`
- `Vender Banking Details.txt`
- `Book.xlsx`
The activity indicated deliberate targeting of credentials and business/financial information rather than indiscriminate file access.

**Finding:** The adversary successfully collected and exfiltrated three files likely containing sensitive organizational information, including VPN credentials and banking-related information. Recommend the organization review these files to validate the information accessed and take follow-on action as needed.

The targeted nature of the collection provided additional evidence that the activity represented a significant compromise rather than an isolated unauthorized authentication.

## All Flags Quick Reference

| Question | Section                     | Flag Name                          | Answer / Finding                                                                     |
| -------- | --------------------------- | ---------------------------------- | ------------------------------------------------------------------------------------ |
| Q00      | Environment Access          | Table Name                         | `Tier-2 hunter ready`                                                                |
| Q01      | Triage                      | Compromised Principal              | `m.smith@lognpacific.org`                                                            |
| Q02      | Triage                      | Flagged Source                     | `103.69.224.136`                                                                     |
| Q03      | Triage                      | Client OS                          | `Linux`                                                                              |
| Q04      | Triage                      | Stored Detection Type              | `anonymizedIPAddress`                                                                |
| Q05      | Triage                      | Audit the Verdict                  | `dismissed`                                                                          |
| Q06      | Triage                      | Live Exposure                      | `ENABLED`                                                                            |
| Q07      | Session Scope               | How the Session Beat MFA           | `singleFactorAuthentication`                                                         |
| Q08      | Session Scope               | Control Surface that Let Them In   | `One Outlook Web`                                                                    |
| Q09      | Session Scope               | Failed Attempts Before Entry       | `two`                                                                                |
| Q10      | Session Scope               | Blast Radius of One Token          | `7`                                                                                  |
| Q11      | Session Scope               | One Continuous Session             | `005d431a-380b-1f5e-e554-16d5010dc28e`                                               |
| Q12      | Directory Recon             | MFA Posture Profiling              | `userRegistrationDetails`                                                            |
| Q13      | Directory Recon             | Group Enumeration                  | `/me/memberOf`                                                                       |
| Q14      | The Fraud                   | Fradulent Request                  | `Updated Banking Details - Pacific IT Monthly`                                       |
| Q15      | The Fraud                   | The Threat They Mined              | `Q1 Vendor Payment Schedule - Review Required`                                       |
| Q16      | The Fraud                   | The Fraud Target                   | `j.reynolds@lognpacific.org`                                                         |
| Q17      | The Fraud                   | Second Channel Reinforcement       | `Microsoft Teams`                                                                    |
| Q18      | Persistence Hunt            | Concealment Rule                   | `Invoice Processing`                                                                 |
| Q19      | Persistence Hunt            | Where the Hidden Mail Goes         | `hide artifacts`                                                                     |
| Q20      | Persistence Hunt            | Exfiltration Rule                  | `merovingian1337@proton.me`                                                          |
| Q21      | Persistence Hunt            | Who Both Rules Target              | `hide responses to Internal Spearphishing emails sent from the compromised account.` |
| Q22      | Data Theft                  | Exfil Operation                    | `FileDownloaded, i filtered the operation types to downloaded`                       |
| Q23      | Data Theft                  | Volume Taken                       | `3, a deliberate pull of specific things`                                            |
| Q24      | Data Theft                  | Credential Documentation           | `VPN-Access-Credentials.txt`                                                         |
| Q25      | Data Theft                  | Vault Pointer                      | `yomark.pdf`                                                                         |
| Q26      | Plant and the Trigger       | Disprove the Inncosent Explanation | `0`                                                                                  |
| Q27      | Plant and the Trigger       | Catch the Plant                    | `Microsoft Flow Portal`                                                              |
| Q28      | Plant and the Trigger       | The Cause Behind the Forward       | `MicrosoftGraphActivityLogs`                                                         |
| Q29      | Plant and the Trigger       | Prove It with the Sequence         | `graph call`                                                                         |
| Q30      | Correlation and Containment | The Automation Source IP           | `20.150.129.194`                                                                     |
| Q31      | Correlation and Containment | Automation Identity                | `7ab7862c-4c57-491e-8a45-d52a7e023983`                                               |
| Q32      | Correlation and Containment | Name the Abused Service            | `Microsoft Power Automate`                                                           |
| Q33      | Correlation and Containment | One Actor, Every Source            | `7`                                                                                  |
| Q34      | Correlation and Containment | Containment Ordering               | `Revoke session`                                                                     |
| Q35      | Correlation and Containment | Where the FLow is REmoved          | `Power Platform Admin Center`                                                        |
| Q36      | Correlation and Containment | The Control that Never Fired       | `not applied, not evaluated by ca`\|\|`                                              |
| Q37      | Correlation and Containment | Why Revoke Before Reset            | `refresh session token survives a reset. a full session revocation kills it.`        |

---
### Attack Chain

```text
Unauthorized Authentication
        ↓
Compromised M365 Identity
        ↓
Internal Email Discovery
        ↓
Targeting of Second Employee
        ↓
Malicious Forwarding / Email Hiding Rules
        ↓
Targeted File Collection
        ↓
Potential Exposure of Credentials & Banking Information
```


---

# Key Findings

1. An adversary successfully authenticated to a targeted Microsoft 365 account from a suspicious external IP following failed authentication attempts.
2. Conditional Access was not applied to the relevant authentication, meaning the expected access control was not evaluated or enforced.
3. The compromised account was subsequently used to target another employee through an existing internal email conversation involving banking information.
4. Malicious email forwarding and hiding rules were established, including forwarding to an external Proton Mail account.
5. The adversary successfully downloaded three sensitive files and ==exfiltrated to an external Proton Mail account==:
   - `VPN Access Creds.txt`
   - `Vender Banking Details.txt`
   - `Book.xlsx`
6. Microsoft Graph telemetry provided evidence of programmatic Microsoft 365 activity following the unauthorized authentication.
7. The investigation established that the incident was significantly more serious than the initial Low severity assessment indicated.

## Attack Chain
```text
Unauthorized Authentication
        ↓
Compromised M365 Identity
        ↓
Internal Email Discovery
        ↓
Targeting of Second Employee
        ↓
Malicious Forwarding / Email Hiding Rules
        ↓
Targeted File Collection
        ↓
Potential Exposure of Credentials & Banking Information
```

## Containment and Remediation
The recommended response prioritized terminating adversary access before investigating the remaining affected resources.

1. **Revoke User Access:** Revoke active sessions and authentication tokens for affected accounts to prevent the adversary from maintaining access through existing authentication artifacts.
2. **Reset Credentials:** Reset passwords for the two affected user accounts.
3. **Remove Malicious Email Rules:** Delete the malicious forwarding and email-archiving rules established by the adversary.
4. **Review Affected Files:** Review the three identified files to determine what information was exposed and whether additional sensitive data was accessed.
5. **Review Conditional Access Coverage:** Investigate why Conditional Access was not applied to the relevant authentication and identify whether additional policies or authentication controls are required.

# Investigation Challenges and Lessions Learned

### Authentication Timeline Reconstruction

Initially, I relied primarily on `TimeGenerated` when reviewing `SigninLogs`. During the investigation, I learned that `CreatedDateTime` can be important when reconstructing the chronological sequence of authentication activity.
**Lesson:** Understand the semantics of timestamp fields rather than assuming the ingestion timestamp represents the precise event sequence.

### Entra Authentication Result Codes

The initial search did not identify the expected failed authentication attempts because the Sentinel time range excluded the earlier events.
Filtering for `ResultType == 50126` after expanding the time range exposed the two relevant failures.
**Lesson:** Validate both the query logic and the investigation time range before concluding that telemetry does not exist.

### Microsoft Graph Investigation

Microsoft Graph activity was initially unfamiliar and required additional research to interpret.
Investigation of `MicrosoftGraphActivityLogs` demonstrated how API telemetry can provide visibility into programmatic Microsoft 365 activity that may not be obvious from authentication or application logs alone.
**Lesson:** Cloud investigations require understanding how authentication, API activity, and application telemetry complement one another.

### Cross-Table Investigation

Several findings required moving between `SigninLogs`, `EmailEvents`, `CloudAppEvents`, and `MicrosoftGraphActivityLogs`.
**Lesson:** A single telemetry source rarely tells the complete story during a cloud identity investigation. Correlating multiple data sources was essential to reconstructing the attack chain.

### Conditional Access Analysis

The investigation initially became more complicated than necessary when determining why the relevant access control did not prevent the authentication.

The key finding was that Conditional Access was not applied and therefore was not evaluated or enforced for the relevant authentication.

**Lesson:** When investigating security controls, first determine whether the control was actually invoked before investigating why it failed.

### AI-Assisted Investigation

AI tools (ChatGPT and Microsoft Copilot) were used during the investigation to clarify unfamiliar Microsoft Graph concepts, validate KQL approaches, and assist with interpreting unfamiliar telemetry.

The resulting information was independently evaluated against the available Sentinel and Defender telemetry before being incorporated into the investigation.

**Lesson:** AI can accelerate research and help bridge knowledge gaps, but analyst judgment and validation against the underlying evidence remains essential. 

# What I Learned
This investigation strengthened my ability to:

- Investigate Microsoft 365 identity compromise using Sentinel and Defender XDR.
- Analyze Entra ID authentication activity using `SigninLogs`.
- Interpret authentication result codes and authentication timelines.
- Investigate Microsoft Graph API activity.
- Correlate identity, email, application, and API telemetry.
- Identify BEC behaviors including internal targeting and malicious email rules.
- Investigate targeted data collection within Microsoft 365.
- Evaluate Conditional Access as part of an identity compromise investigation.
- Translate individual telemetry findings into a broader attack narrative.

---
#### Disclaimer
This report is based on a controlled Cyber Range. All systems, users, domains, IP addresses, files, hashes, email addresses, and passwords referenced in this document are simulated for training and investigation practice. No real infrastructure, organization, or individuals are represented.
