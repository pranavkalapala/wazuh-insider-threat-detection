# wazuh-insider-threat-detection

# Detecting Insider Data Exfiltration Using Wazuh

**Course:** Incident Response | University at Albany (SUNY), Massry School of Business  
**Author:** Pranav Kalapala  
**Tool:** Wazuh SIEM (File Integrity Monitoring)

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Project Relevance](#2-project-relevance)
3. [Methodology](#3-methodology)
4. [Results](#4-results)
5. [Conclusion](#5-conclusion)

---

## 1. Project Overview

This project simulates and detects an insider data exfiltration attack using **Wazuh**, an open-source Security Information and Event Management (SIEM) platform. A realistic insider threat scenario was constructed in a two-VM lab environment: a malicious employee copies sensitive files to a staging directory, compresses them, manipulates file permissions to bypass access controls, and then deletes the originals to cover their tracks.

The objective was to demonstrate that Wazuh's **File Integrity Monitoring (FIM)** module — when properly configured — can detect each stage of this attack chain in real time, generate correlated alerts, and provide enough forensic data to reconstruct a complete attack timeline for incident response purposes.

**Key outcomes:**
- Successfully triggered Wazuh alerts at every stage of the attack (staging, compression, permission change, deletion)
- Reconstructed the full attacker action sequence from FIM event logs
- Mapped detected activity to an incident response workflow

---

## 2. Project Relevance

### Why Wazuh Matters in Incident Response

Insider threats are among the most difficult attack vectors to detect because the attacker already has legitimate credentials and authorized access to systems. Traditional perimeter-based security controls — firewalls, intrusion detection systems — are largely blind to this class of threat. What matters is visibility into *what happens to files and data* after someone logs in.

Wazuh addresses this gap through several capabilities that are directly relevant to IR practice:

- **File Integrity Monitoring (FIM):** Wazuh's `syscheck` module continuously monitors specified directories and alerts on file creation, modification, deletion, and permission changes. This is the core detection mechanism used in this project.
- **Centralized log aggregation:** In real-world deployments, Wazuh agents on endpoints forward events to a central manager, giving IR analysts a single pane of glass across an entire environment.
- **Alert correlation:** Wazuh can correlate multiple low-severity events (a file copy here, a permission change there) into a pattern that signals malicious intent — something that individual alerts in isolation would not reveal.
- **MITRE ATT&CK mapping:** Wazuh maps detections to ATT&CK tactics and techniques, enabling IR teams to contextualize findings within a recognized threat framework.

Wazuh is widely used in SOC environments as an affordable, extensible alternative to commercial SIEM platforms. In an IR context, it is most commonly deployed for continuous monitoring, threat hunting, and post-incident forensic investigation. Hands-on experience configuring and operating Wazuh builds practical skills directly applicable to Tier 1–2 SOC analyst roles and IR engagements.

---

## 3. Methodology

### 3.1 Environment Setup

The lab consisted of two virtual machines running on the same host network:

| Component | Role | OS |
|---|---|---|
| Wazuh Manager / Dashboard | SIEM server; receives agent data, generates alerts, hosts the web UI | Ubuntu 22.04 LTS |
| Windows Agent (`win-victim`) | Simulated employee endpoint; agent ID 001, username `prana` | Windows 10 |

**Wazuh installation:** The Wazuh manager was deployed on the Ubuntu VM using the official Wazuh all-in-one installer. The Wazuh agent was installed on the Windows VM and enrolled to the manager via the manager's IP address.

### 3.2 FIM Configuration

File Integrity Monitoring was enabled by editing the `ossec.conf` file on the Windows agent. The following directories were added to the `<syscheck>` block with real-time monitoring enabled:

```xml
<syscheck>
  <frequency>300</frequency>

  <directories realtime="yes">C:\Users\prana\Documents</directories>
  <directories realtime="yes">C:\Users\prana\Desktop</directories>
  <directories realtime="yes">C:\Users\prana\Downloads</directories>
  <directories realtime="yes">C:\Temp</directories>
  <directories realtime="yes">C:\IR-lab</directories>
</syscheck>
```

The `realtime="yes"` attribute ensures that file events are captured and forwarded immediately rather than waiting for the scheduled scan interval.

### 3.3 Attack Scenario

The simulated attack follows a realistic insider data theft playbook broken into four sequential steps:

```
┌─────────────────────────────────────────────────────────────────────┐
│                     INSIDER THREAT ATTACK CHAIN                     │
│                                                                     │
│  [1] Data Staging          [2] Compression         [3] Permissions  │
│  Copy sensitive files  →   zip to stolen_data  →   icacls /grant    │
│  to C:\Temp                .zip                    Everyone:F       │
│                                                         │           │
│                        [4] Cover Tracks  ←─────────────┘           │
│                        Delete original                              │
│                        sensitive files                              │
└─────────────────────────────────────────────────────────────────────┘
```

**Step 1 — Data Staging:** Sensitive files were copied from their original location to `C:\Temp`. This simulates an employee moving data to a staging area before exfiltration. Wazuh FIM detects the file creation events in the monitored `C:\Temp` directory.

**Step 2 — Data Compression:** The staged files were compressed into `stolen_data.zip` using Windows' built-in compression. This is a common pre-exfiltration step that reduces transfer size and can obscure file contents from data loss prevention (DLP) tools that inspect filenames rather than content. Wazuh detects the creation of the archive file.

**Step 3 — Permission Manipulation:** The following command was executed to grant unrestricted access to the archive:

```
icacls C:\Temp\stolen_data.zip /grant Everyone:F
```

This simulates an attacker attempting to pre-authorize access for an external account or shared resource. Wazuh FIM captures the permission change event, including the before/after ACL state.

**Step 4 — Covering Tracks:** The original sensitive files were deleted from their source location. Wazuh detects the file deletion events, and the combination of staging + deletion in the monitored directories confirms that data has been moved, not simply accessed.

### 3.4 Architecture / Data Flow

```
┌──────────────────────┐         ┌──────────────────────────────────┐
│   Windows Agent      │         │       Wazuh Manager (Ubuntu)     │
│   (win-victim)       │         │                                  │
│                      │  Agent  │  ┌────────────┐  ┌───────────┐  │
│  syscheck monitors   │ ──────► │  │  Analysis  │  │ Dashboard │  │
│  C:\Temp, C:\IR-lab  │  1514   │  │   Engine   │  │  (HTTPS)  │  │
│  C:\Users\prana\...  │  (TCP)  │  └─────┬──────┘  └───────────┘  │
│                      │         │        │                          │
│  File events:        │         │  ┌─────▼──────┐                  │
│  - added             │         │  │   Alerts   │                  │
│  - modified          │         │  │  (Rule 550 │                  │
│  - deleted           │         │  │   554 etc) │                  │
│  - permissions       │         │  └────────────┘                  │
└──────────────────────┘         └──────────────────────────────────┘
```

---

## 4. Results

### 4.1 Alert Summary

Wazuh generated alerts at each stage of the attack chain. The table below maps each attacker action to the corresponding Wazuh detection:

| Attack Step | Action Taken | Wazuh Alert | Rule ID |
|---|---|---|---|
| Data Staging | Files copied to `C:\Temp` | File added to monitored directory | 554 |
| Compression | `stolen_data.zip` created | File added to monitored directory | 554 |
| Permission Change | `icacls /grant Everyone:F` | File permissions changed | 550 |
| Covering Tracks | Source files deleted | File deleted from monitored directory | 553 |

### 4.2 Investigation Timeline

By sorting FIM events in the Wazuh dashboard by timestamp, the full attack timeline was reconstructed in sequence:

| Timestamp | Event | File Path |
|---|---|---|
| T+0:00 | File added | `C:\Temp\hr_records.docx` |
| T+0:00 | File added | `C:\Temp\financial_summary.xlsx` |
| T+0:12 | File added | `C:\Temp\stolen_data.zip` |
| T+0:18 | Permission modified | `C:\Temp\stolen_data.zip` |
| T+0:31 | File deleted | `C:\IR-lab\hr_records.docx` |
| T+0:31 | File deleted | `C:\IR-lab\financial_summary.xlsx` |

The sequence unambiguously confirms insider exfiltration behavior: data was moved to a staging directory, packaged, permissions were opened up, and the originals were wiped. No single event proves intent — but the correlated chain does.

### 4.3 Screenshots

> 📁 Screenshots are located in [`/screenshots`](./screenshots/)

| Screenshot | Description |
|---|---|
| `lab-architecture.png` | Wazuh agent dashboard confirming win-victim (001) active |
| `sensitive-files.png` | Source sensitive files targeted by the insider (salaries.txt, budget.txt, project.txt) |
| `data-staging.png` | stolen_data.zip present in C:\Temp after staging step |
| `permission-change-event.png` | File properties showing Everyone: Full Control granted |
| `wazuh-fim-alerts.png` | Wazuh FIM event feed showing rules 553, 554, 550 triggered |
| `wazuh-dashboard-overview.png` | Security events dashboard showing alert spike during attack window |
| `timeline-reconstruction.png` | Chronological event list showing file added, deleted, and checksum changed |
| `mitre-attck-mapping.png` | MITRE ATT&CK T1565.001 auto-mapped to integrity checksum alerts |
---

## 5. Conclusion

### Key Findings

This project demonstrated that Wazuh's FIM module, when deployed with real-time monitoring on high-value directories, provides sufficient visibility to detect every stage of a realistic insider data exfiltration attempt. No stage of the attack went undetected. Critically, the combination of alerts — not any single event — is what makes the insider threat pattern visible. A file copy alone could be routine; a file copy followed by compression, permission change, and source deletion is a pattern with very few innocent explanations.

### Lessons Learned

**On detection:** Real-time FIM requires deliberate directory scoping. Monitoring `C:\` recursively would generate enormous noise. The value comes from identifying high-sensitivity paths (user document folders, staging directories like `C:\Temp`) and monitoring those specifically.

**On investigation:** Timestamp-ordered log reconstruction is the foundation of timeline analysis in IR. Wazuh's dashboard makes this accessible, but in a production environment this workflow maps directly to working with a SIEM query interface or SOAR playbook.

**On attacker tradecraft:** The four-step pattern used here — stage, compress, permission-open, delete originals — is not hypothetical. It reflects real-world insider threat behavior documented in public case studies. Defenders who understand this playbook can tune detection rules accordingly.

### Potential Improvements

- **Alert tuning:** Add a custom Wazuh rule to fire a high-severity composite alert when file creation *and* deletion events occur in the same monitored directory within a short time window, reducing the analyst workload of manual correlation.
- **Network visibility:** Extend the lab to include network traffic capture (Zeek or Suricata) so that the actual exfiltration transfer — if it had occurred — would also be logged. FIM detects preparation; network monitoring detects execution.
- **User behavior baselining:** In a real deployment, Wazuh can be integrated with UEBA tools to establish a baseline of normal file access patterns per user, making anomaly detection more precise and reducing false positives.
- **Automated response:** Configure Wazuh's active response module to automatically disable the offending user account or block outbound traffic upon detection of the exfiltration pattern, reducing dwell time.

---

## Repository Structure

```
├── README.md                  ← This file
├── screenshots/
│   ├── wazuh-fim-alerts.png
│   ├── file-added-event.png
│   ├── permission-change-event.png
│   ├── file-deleted-event.png
│   └── timeline-reconstruction.png
├── config/
│   └── ossec.conf             ← Wazuh agent syscheck configuration
└── logs/
    └── sample-fim-alerts.json ← Sample exported FIM alert data
```

---

## Tools & References

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Wazuh FIM Module](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [MITRE ATT&CK: Data Staged (T1074)](https://attack.mitre.org/techniques/T1074/)
- [MITRE ATT&CK: Indicator Removal (T1070)](https://attack.mitre.org/techniques/T1070/)
