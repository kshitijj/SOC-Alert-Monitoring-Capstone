# 🛡️ SOC Alert Monitoring & Log Correlation Capstone

> A practical Blue Team cybersecurity project demonstrating endpoint monitoring, log correlation, network traffic analysis, MITRE ATT&CK mapping, IOC extraction, and automated incident reporting.

---

## 📌 Project Overview

This project simulates the workflow of a Tier-1 Security Operations Center (SOC) Analyst by collecting, analyzing, and correlating security events from multiple sources.

The project combines Windows endpoint monitoring, authentication log analysis, network traffic inspection, threat intelligence mapping, and a Python-based SOC Incident Analyzer to investigate simulated attack activity.

The objective is to demonstrate real-world Blue Team investigation techniques using industry-standard tools.

---

# 🎯 Objectives

- Monitor Windows endpoint activity using Sysmon
- Analyze Windows Security Events
- Capture and inspect network traffic with Wireshark
- Simulate reconnaissance using Kali Linux and Nmap
- Correlate endpoint, authentication, and network logs
- Extract Indicators of Compromise (IOCs)
- Map detections to the MITRE ATT&CK Framework
- Generate structured incident reports

---

# 🏗️ Project Workflow

```
Attacker (Kali Linux)
        │
        ▼
Nmap Reconnaissance Scan
        │
        ▼
Windows Target Machine
        │
        ├── Sysmon Logs
        ├── Windows Event Logs
        └── Network Connections
               │
               ▼
Wireshark Packet Capture
               │
               ▼
Python SOC Incident Analyzer
               │
               ├── Log Correlation
               ├── IOC Extraction
               ├── Risk Scoring
               ├── MITRE ATT&CK Mapping
               └── Incident Report
```

---

# 🛠️ Technologies Used

| Category | Tools |
|----------|-------|
| Operating System | Windows 11 |
| Endpoint Monitoring | Sysmon |
| Event Analysis | Windows Event Viewer |
| Network Analysis | Wireshark |
| Attack Simulation | Kali Linux |
| Reconnaissance | Nmap |
| Programming | Python |
| Virtualization | VMware Workstation Pro |
| Threat Framework | MITRE ATT&CK |

---

# 🚨 Key Features

- Endpoint Monitoring
- Windows Event Analysis
- Network Packet Analysis
- IOC Extraction
- Risk Scoring
- MITRE ATT&CK Mapping
- Attack Timeline Correlation
- Automated Incident Report Generation
- Live SOC Dashboard
- Incident Severity Classification

---

# 📂 Repository Structure

```
SOC-Alert-Monitoring-Capstone
│
├── docs
│   ├── SOC_Capstone_Report.docx
│   ├── SOC_Capstone_Presentation.pdf
│   └── SOC_Capstone_Presentation.pptx
│
├── Screenshots
│
├── SOC_Incident_Analyzer_v4
│   ├── main.py
│   ├── dashboard.py
│   ├── parser.py
│   ├── report_generator.py
│   ├── soc_engine.py
│   ├── utils.py
│   ├── sample_logs.txt
│   ├── mitre_mapping.json
│   └── requirements.txt
│
└── README.md
```

---

# 📸 Project Screenshots

The repository includes screenshots demonstrating:

- Windows IP Configuration
- Kali Linux Nmap Scan
- Sysmon Process Creation (Event ID 1)
- Sysmon Network Connection (Event ID 3)
- Windows Failed Logon (4625)
- Windows Successful Logon (4624)
- Wireshark TCP Analysis
- SOC Incident Analyzer Dashboard
- MITRE ATT&CK Mapping
- IOC Panel
- Executive Summary
- Incident Summary
- Generated Incident Report

---

# 🧠 MITRE ATT&CK Mapping

Examples of mapped techniques include:

| Technique | Description |
|-----------|-------------|
| T1071.001 | Application Layer Protocol |
| T1547 | Registry Run Keys / Startup Folder |
| T1059 | Command and Scripting Interpreter |
| T1046 | Network Service Discovery |

---

# 📊 SOC Incident Analyzer

The custom Python SOC Incident Analyzer performs:

- Log Parsing
- Incident Detection
- IOC Extraction
- Attack Timeline Correlation
- MITRE ATT&CK Mapping
- Risk Score Calculation
- Executive Summary Generation
- Automated Incident Reporting

---

# 💼 Skills Demonstrated

- Security Operations Center (SOC)
- Blue Team Operations
- Endpoint Monitoring
- Windows Security
- Log Correlation
- Threat Detection
- IOC Analysis
- Incident Response
- Network Traffic Analysis
- Python Automation
- MITRE ATT&CK
- Security Reporting

---

# 📈 Project Outcome

This project demonstrates an end-to-end SOC investigation workflow by integrating endpoint monitoring, authentication log analysis, network traffic inspection, IOC extraction, MITRE ATT&CK mapping, and automated incident reporting into a unified defensive security solution.

The project reflects practical SOC analyst responsibilities and highlights investigative, analytical, and reporting skills commonly required in entry-level cybersecurity roles.

---

# 🚀 Future Improvements

- Integration with Microsoft Sentinel or Splunk
- Real-time Sysmon log ingestion
- Sigma Rule support
- YARA rule integration
- Threat Intelligence API integration
- Automated alert notifications
- Interactive web dashboard

---

# 👨‍💻 Author

**Kshitij**

Cybersecurity Enthusiast | Blue Team | SOC Analyst Aspirant

---

## ⭐ If you found this project interesting, consider giving it a Star!
