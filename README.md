# M365-Identity-Compromise-BEC-Threat-Hunt_SecondVector


**Title:** Second Vector Threat Hunt: M365 Identity Compromise & Business Email Compromise\
**Date:** 2026-08-10\
**Environment:** Microsoft Defender XDR, Microsoft Sentinel, Microsoft 365 / Entra ID\
**Source:** Log(N) Pacific Cyber Range - Hunt 08\
**Incident:** Microsoft XDR Incident 87241

## 🛡️Overview

**Objective:** Investigate a simulated Microsoft Entra incident and determine whether an initially low-risk anonymous IP address sign-in represented a broader compromise and Business Email Compromise (BEC) campaign.

**Environment:** Microsoft Defender XDR, Microsoft Sentinel, Microsoft 365 / Microsoft Entra ID

**Data Sources:**
- `SigninLogs`
- `OfficeActivity`
- `MicrosoftGraphActivityLogs`
- `EmailEvents`
- `CloudAppEvents`
- `AuditLogs`

**Tools:** KQL, Microsoft Sentinel, Microsoft Defender XDR, Microsoft 365 / Entra ID

**Scenario:**  
This investigation was conducted as part of the Log(N) Pacific Cyber Range. The investigation began with an XDR incident that had initially been rated Low by a previous SOC shift. The objective was to determine whether that assessment accurately reflected the scope of the activity and identify what the adversary accomplished after gaining access.

---

# 🔍Investigation Scope

The investigation focused on four primary intelligence gaps:

1. Determine whether the Low severity assessment accurately reflected the incident.
2. Identify what the adversary did after gaining access and what information they accessed or collected.
3. Determine whether persistence or continued access mechanisms were established.
4. Identify whether additional users were targeted or drawn into the activity.

---

# 🧭 Investigation

## 1. Initial Authentication & Identity Risk

**Objective:** Identify the affected Microsoft 365 account and establish the context of the suspicious sign-in.

**Approach:** `SigninLogs` was reviewed following the Defender XDR alert.

```kql
SigninLogs
| sort by TimeGenerated desc
```

**Finding:** The investigation identified suspicious sign-in activity involving `m.smith@lognpacific.org` from anonymous IP address `103.69.224.136`. The Defender XDR alert classification initiated the investigation. The IP was geolocated to the Netherlands and was inconsistent with the user's expected location, providing additional evidence of unauthorized access.

---

## 2. Suspicious Successful Sign-In

**Approach:** `SigninLogs` was filtered for the suspicious IP address and affected account.

```kql
SigninLogs
| where IPAddress contains "224.136"
| where Identity contains "Smith"
| where ResultSignature contains "success"
```

During timeline reconstruction, `CreatedDateTime` was found to provide a more appropriate reference for the chronological sequence of sign-in events than `TimeGenerated`.

**Finding:** A successful sign-in from `103.69.224.136` was identified. The evidence supported an unauthorized successful sign-in rather than session hijacking.

---

## 3. Failed Sign-In Attempts

**Approach:** Entra authentication result code `50126` was used to identify failed sign-in attempts.

```kql
SigninLogs
| where IPAddress contains "224.136"
| where Identity contains "Smith"
| where ResultSignature contains "failure"
| where ResultType contains "50126"
```

The investigation window was expanded after the initial search excluded earlier events.

**Finding:** Two failed sign-in attempts preceded the successful sign-in from `103.69.224.136`, establishing attempted unauthorized access before successful account entry.

---

## 4. Post-Authentication Application Activity

**Approach:** Successful sign-ins from the suspicious IP were reviewed to identify accessed Microsoft 365 applications and associated session activity.

```kql
SigninLogs
| where IPAddress == "103.69.224.136"
| where UserPrincipalName =~ "m.smith@lognpacific.org"
| where ResultType == "0"
| summarize DistinctApps = dcount(AppDisplayName)
```

```kql
SigninLogs
| where IPAddress contains "224.136"
| where Identity contains "Smith"
| where ResultSignature contains "success"
| summarize Frequency = count() by SessionId
```

**Finding:** The successful sign-in was followed by activity across multiple Microsoft 365 applications. The subsequent activity was associated with meaningful account activity rather than an isolated authentication event.

---

## 5. Microsoft Graph Activity

**Approach:** `MicrosoftGraphActivityLogs` was reviewed for API activity associated with the suspicious IP and compromised account.

```kql
MicrosoftGraphActivityLogs
| where IPAddress == "103.69.224.136"
| where RequestUri has "/reports/"
| project TimeGenerated, RequestUri
| order by TimeGenerated asc
```

Additional requests involving `/me/` and `/me/memberOf` were reviewed to identify account and directory reconnaissance.

**Finding:** The threat actor used Microsoft Graph to perform programmatic reconnaissance of the compromised Microsoft 365 identity, including MFA registration and directory membership information.

---

## 6. Internal Targeting and Business Email Compromise

**Approach:** `EmailEvents` was reviewed for activity associated with the suspicious IP and payment-related subjects.

```kql
EmailEvents
| where TimeGenerated between (datetime(2026-06-11 03:00)..datetime(2026-06-11 13:00))
| where SenderIPv4 == "103.69.224.136"
| project TimeGenerated, SenderIPv4, RecipientEmailAddress, Subject
```

A broader search identified the existing conversation:

`Q1 Vendor Payment Schedule - Review Required`

```kql
EmailEvents
| where TimeGenerated between (datetime(2026-01-01 03:00)..datetime(2026-06-11 13:00))
| where Subject contains "payment" or Subject contains "approval process"
| project TimeGenerated, Subject, SenderIPv4, RecipientEmailAddress
```

**Finding:** The threat actor leveraged an existing payment-related conversation in `m.smith@lognpacific.org`'s mailbox to send a fraudulent payment-information request to `j.reynolds@lognpacific.org`. This behavior is consistent with **MITRE ATT&CK T1534 - Internal Spearphishing**.

`CloudAppEvents` also showed a Microsoft Teams message reinforcing the same fraudulent payment-information pretext, demonstrating multi-channel social engineering.

---

## 7. Malicious Email Forwarding and Hiding Rules

**Approach:** `OfficeActivity` was reviewed for mailbox-rule creation.

```kql
OfficeActivity
| where TimeGenerated between (datetime(2026-06-11 00:00)..datetime(2026-06-12 00:00))
| where Operation contains "New-InboxRule"
```

**Finding:** The threat actor established two mailbox-rule behaviors:

* A concealment rule designed to hide or archive relevant responses.
* An external forwarding rule directing selected email to `merovingian1337@proton.me`.

The concealment behavior aligns with **MITRE ATT&CK T1564.008 - Email Hiding Rules**. The external forwarding behavior aligns with **T1114.003 - Email Forwarding Rule**.

The investigation did not test whether the forwarding rule remained effective after containment, so continued access is described as a potential mechanism rather than confirmed persistence.

---

## 8. Targeted Data Collection

**Approach:** `CloudAppEvents` was filtered for `FileDownloaded` activity associated with the compromised account.

```kql
CloudAppEvents
| where ActionType == "FileDownloaded"
| where Timestamp between (datetime(2026-06-11 00:00)..datetime(2026-06-12 00:00))
| where AccountDisplayName =~ "m.smith@lognpacific.org"
| extend FileName = tostring(RawEventData.SourceFileName)
| extend SiteUrl = tostring(RawEventData.SiteUrl)
| order by Timestamp asc
```

**Finding:** The threat actor downloaded three targeted files:

* `VPN Access Creds.txt`
* `Vender Banking Details.txt`
* `Book.xlsx`

The files were downloaded in the same second, indicating a deliberate collection of credential, banking, and business information rather than indiscriminate file access.

A separate `FileAccessed/View` event was identified for `yomark.pdf`, but the file was not downloaded. The activity was assessed as consistent with a potential credential-store pointer in the context of **MITRE ATT&CK T1555 - Credentials from Password Stores**.

The investigation confirmed targeted collection but did not establish that the three downloaded files themselves were exfiltrated. Separately, the mailbox forwarding rule demonstrated that email content was capable of being sent to the external Proton Mail account.

---

## 9. Power Automate Abuse and Automated Access

**Approach:** Microsoft Graph, Microsoft 365 application, and Power Automate activity were correlated to identify automation established during the compromise.

The investigation identified activity involving the Microsoft Flow Portal followed by an OAuth grant associated with application ID:

`7ab7862c-4c57-491e-8a45-d52a7e023983`

Subsequent Graph activity from Microsoft-owned Azure infrastructure used the same application identity and accessed the compromised mailbox through the `/me/messages/.../forward` endpoint.

**Finding:** The threat actor established a Power Automate flow with delegated OAuth access to the compromised mailbox.

The flow subsequently operated through Microsoft-owned Azure infrastructure rather than the threat actor's original source IP and forwarded mailbox content to `merovingian1337@proton.me`.

This demonstrated a separation between the threat actor's interactive activity and subsequent automated cloud activity, creating a mechanism for continued mailbox access without requiring the threat actor to maintain the original interactive session.


## 🚩 All Flags Quick Reference

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
| Q36      | Correlation and Containment | The Control that Never Fired       | `not applied, not evaluated by ca`                                              |
| Q37      | Correlation and Containment | Why Revoke Before Reset            | `refresh session token survives a reset. a full session revocation kills it.`        |

---

# 🚨Key Findings

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

## 🔗 Attack Chain
```text
Unauthorized Authentication (Sign-In)
        ↓
Compromised M365 Account
        ↓
Internal Email Discovery
        ↓
Internal Spearphishing / BEC
        ↓
Microsoft Teams Reinforcement 
        ↓
Malicious Forwarding / Email Hiding Rules via Power Automate Flow
        ↓
Targeted File Collection
        ↓
Potential Exposure of Sensitive Information
```

## ⚠️Containment and Remediation
The recommended response prioritized terminating adversary access before investigating the remaining affected resources.

1. **Revoke User Access:** Revoke active sessions and authentication tokens for affected accounts to prevent the adversary from maintaining access through existing authentication artifacts.
2. **Reset Credentials:** Reset passwords for the two affected user accounts.
3. **Remove Malicious Email Rules:** Delete the malicious forwarding and email-archiving rules established by the adversary.
4. **Disable or Remove the Malicious Power Automate Flow**: Investigate and remove the compromised Power Automate flow and revoke the associated OAuth permissions/application access.
5. **Review Affected Files:** Review the three identified files to determine what information was exposed and whether additional sensitive data was accessed.
6. **Review Conditional Access Coverage:** Investigate why Conditional Access was not applied to the relevant authentication and identify whether additional policies or authentication controls are required.
7. **Review External Mail Forwarding**: Investigate the external forwarding destination and determine what mailbox content was successfully forwarded outside the organization.
8. **Review the Targeted User**: Investigate `j.reynolds@lognpacific.org` for related malicious messages, mailbox rules, file access, and potential account compromise.

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

# 💭 What I Learned
This investigation strengthened my ability to:

- Investigate Microsoft 365 identity compromise using Sentinel and Defender XDR.
- Analyze Entra ID authentication activity using `SigninLogs`.
- Interpret authentication result codes and authentication timelines.
- Investigate Microsoft Graph API activity.
- Correlate identity, email, application, and API telemetry.
- Identify BEC behaviors including internal targeting and malicious email rules.
- Investigate targeted data collection within Microsoft 365.
- Evaluate Conditional Access as part of an identity compromise investigation.
- Investigate Power Automate and OAuth activity associated with a compromised account.
- Translate individual telemetry findings into a broader attack narrative.
- Distinguish evidence of data collection from evidence of confirmed exfiltration.

---
#### Disclaimer
This report is based on a controlled Cyber Range. All systems, users, domains, IP addresses, files, hashes, email addresses, and passwords referenced in this document are simulated for training and investigation practice. No real infrastructure, organization, or individuals are represented.
