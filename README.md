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
- Due to a compromised device, the unauthorized entity performed lateral movement and discovered a critical server `azuki-fileserver01` through remote share enumuration. The threat actor then continued to probe for privilege and network enumeration. They then implemented a staging directory and began steps for defensve evasion by attempting to hide the staging directory path through obfuscation. Using legitimate system utilities with network capabilities, the unauthorized entity then weaponized "Living off the Land" techniques to a script into the staging directory. The C2 IP address used to download the script `ex.ps1` was identified as `78.141.196.6:7331` to the staging directory `C:\Windows\Logs\CBS\`. Credential file discovery was used for collection and created the file `IT-Admin-Passwords.csv` within the staging directory. The built-in system utility "xcopy.exe" was used in attempt to reduce the chance of detection of security alerts to stage data from the network share `"xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y`.

## Immediate Actions:
## Stakeholder Impact:
## Customers:
## Business Partners:
## Regulatory Bodies:
## Shareholders:

# Technical Analysis

# Affected Systems & Data

# Evidence Sources & Analysis

# Indicators of Compromise (IoCs)
## C2 IP:

# Root Cause Analysis

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
