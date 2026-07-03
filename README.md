# 🛡️ SOC Alert Monitoring & Log Correlation Capstone

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Windows](https://img.shields.io/badge/Windows-11-0078D6?logo=windows)
![Sysmon](https://img.shields.io/badge/Sysmon-Microsoft-green)
![Wireshark](https://img.shields.io/badge/Wireshark-Network%20Analysis-blue?logo=wireshark)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![VMware](https://img.shields.io/badge/VMware-Workstation-orange)

> **A practical Blue Team cybersecurity project demonstrating endpoint monitoring, log correlation, network traffic analysis, MITRE ATT&CK mapping, IOC extraction, and automated incident reporting.**

---

# 📌 Project Overview

This project simulates the responsibilities of a Tier-1 Security Operations Center (SOC) Analyst by collecting, analyzing, and correlating security events from multiple sources.

The project combines Windows endpoint monitoring, Windows Security Event analysis, network traffic inspection, threat intelligence mapping, and a custom Python-based SOC Incident Analyzer to investigate simulated attack activity.

The objective is to demonstrate practical Blue Team investigation techniques using widely adopted cybersecurity tools and industry best practices.

---

# 🎯 Project Objectives

- Monitor Windows endpoint activity using Sysmon
- Analyze Windows Security Events
- Capture and inspect network traffic using Wireshark
- Simulate reconnaissance using Kali Linux and Nmap
- Correlate endpoint, authentication, and network logs
- Extract Indicators of Compromise (IOCs)
- Map detections to the MITRE ATT&CK Framework
- Generate structured incident reports

---

# 🏗️ Project Workflow

```text
Attacker (Kali Linux)
        │
        ▼
Nmap Reconnaissance Scan
        │
        ▼
Windows Target Machine
        │
        ├── Sysmon Logs
        ├── Windows Security Events
        └── Network Connections
               │
               ▼
Wireshark Packet Capture
               │
               ▼
SOC Incident Analyzer (Python)
               │
               ├── Log Correlation
               ├── IOC Extraction
               ├── Risk Scoring
               ├── MITRE ATT&CK Mapping
               └── Incident Report Generation
```

---

# 📊 Project Results

- ✅ Successfully monitored endpoint activity using Sysmon
- ✅ Captured and analyzed Windows Security Events
- ✅ Correlated endpoint, authentication, and network logs
- ✅ Detected **9 simulated security incidents**
- ✅ Extracted **13 Indicators of Compromise (IOCs)**
- ✅ Calculated an overall **HIGH** risk score (**69/100**)
- ✅ Generated automated incident reports
- ✅ Mapped detected activity to the MITRE ATT&CK Framework

---

# 🛠️ Technologies Used

| Category | Technology |
|----------|------------|
| Operating System | Windows 11 |
| Endpoint Monitoring | Sysmon |
| Log Analysis | Windows Event Viewer |
| Network Analysis | Wireshark |
| Attack Simulation | Kali Linux |
| Reconnaissance | Nmap |
| Programming | Python |
| Virtualization | VMware Workstation Pro |
| Threat Intelligence | MITRE ATT&CK |

---

# 🚨 Key Features

- Endpoint Monitoring
- Windows Event Analysis
- Network Packet Analysis
- Log Correlation
- IOC Extraction
- Risk Score Calculation
- MITRE ATT&CK Mapping
- Attack Timeline Correlation
- Live SOC Dashboard
- Automated Incident Report Generation

---

# 📂 Repository Structure

```text
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
│   ├── config.json
│   └── requirements.txt
│
└── README.md
```

---

# 📸 Project Screenshots

## Windows Endpoint Monitoring

![Sysmon Process Creation](Screenshots/03_Sysmon_EventID1_Process_Creation.png.png)

---

## Network Traffic Analysis

![Wireshark](Screenshots/07_Wireshark_TCP_Handshake.png.png)

---

## SOC Incident Analyzer Dashboard

![Dashboard](Screenshots/10_IncidentAnalyzer_Dashboard.png.jpeg)

---

## MITRE ATT&CK Mapping

![MITRE Mapping](Screenshots/11_IncidentAnalyzer_MITRE_Mapping.png.jpeg)

---

## Executive Summary

![Executive Summary](Screenshots/12_Report_Executive_Summary.png.jpeg)

---

# 🧠 MITRE ATT&CK Mapping

Example techniques detected during analysis:

| Technique | Description |
|-----------|-------------|
| T1071.001 | Application Layer Protocol |
| T1547 | Registry Run Keys / Startup Folder |
| T1059 | Command and Scripting Interpreter |
| T1046 | Network Service Discovery |

---

# 📊 SOC Incident Analyzer

The custom Python SOC Incident Analyzer provides:

- Log Parsing
- Security Event Classification
- Incident Detection
- IOC Extraction
- Attack Timeline Correlation
- Risk Score Calculation
- MITRE ATT&CK Mapping
- Executive Summary Generation
- Automated Incident Report Creation

---

# 🚀 Running the Project

```bash
git clone https://github.com/kshitijj/SOC-Alert-Monitoring-Capstone.git

cd SOC-Alert-Monitoring-Capstone/SOC_Incident_Analyzer_v4

pip install -r requirements.txt

python main.py
```

---

# 💼 Skills Demonstrated

- Security Operations Center (SOC)
- Blue Team Operations
- Endpoint Monitoring
- Windows Security
- Log Correlation
- Threat Detection
- Incident Response
- IOC Analysis
- Network Traffic Analysis
- Python Automation
- MITRE ATT&CK Framework
- Security Reporting

---

# 📈 Project Outcome

This project demonstrates an end-to-end SOC investigation workflow by integrating endpoint monitoring, authentication log analysis, network traffic inspection, IOC extraction, MITRE ATT&CK mapping, and automated incident reporting into a unified defensive security solution.

The project reflects practical SOC analyst responsibilities and showcases analytical, investigative, and reporting skills expected in entry-level cybersecurity roles.

---

# 🔮 Future Enhancements

- Microsoft Sentinel Integration
- Splunk Log Ingestion
- Sigma Rule Detection
- YARA Rule Support
- Threat Intelligence API Integration
- Automated Email Alerts
- Interactive Web Dashboard

---

# 📄 License

This project is intended for educational and portfolio purposes.

---

# 👨‍💻 Author

**Kshitij**

Cybersecurity Enthusiast • Blue Team • SOC Analyst Aspirant

---

⭐ **If you found this project useful, consider giving it a Star!**
