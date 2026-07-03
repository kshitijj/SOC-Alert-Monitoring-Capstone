# SOC Incident Analyzer v3.0

A professional SOC analyst portfolio project demonstrating Blue Team skills, MITRE ATT&CK mapping, incident detection, IOC extraction, and risk scoring.

Inspired by Microsoft Sentinel, Splunk Enterprise Security, IBM QRadar, and Wazuh.

---

## Features

- **SOC Dashboard** — Live alert counts, risk gauge, top IPs/users/hosts, MITRE summary
- **Incident Cards** — Full 15-field cards: ID, Technique, Tactic, Confidence, Risk Score, IPs, User, Host, Process, Evidence
- **Attack Timeline** — Visual attack story with chronological clusters and chain assessments
- **IOC Extraction** — Automatic extraction of IPs, users, processes, hostnames, domains, hashes
- **Evidence Panel** — Raw log evidence per incident with matched rule, IOC, and detection reason
- **MITRE ATT&CK Mapping** — Technique, tactic, description for all detected events
- **Risk Engine** — Weighted severity scoring with progress bar visualization
- **Incident Report** — Professional PDF-ready `.txt` report with all sections

---

## Quick Start

```bash
# No packages required — Standard Library only
python main.py
```

1. Run **option 1** (Analyze Logs) first
2. Explore the dashboard, incident cards, and timeline
3. Generate the incident report with option 9

---

## Menu

| Option | Description |
|--------|-------------|
| 1 | Analyze Logs |
| 2 | SOC Dashboard |
| 3 | Incident Cards |
| 4 | Attack Timeline |
| 5 | IOC Panel |
| 6 | Evidence Panel |
| 7 | Search Event ID |
| 8 | View MITRE Mapping |
| 9 | Generate Incident Report |
| 10 | Help |
| 11 | Exit |

---

## Log Format

Pipe-separated `Key:Value` pairs, one event per line:

```
Timestamp:2026-06-22 10:32:14|EventID:1|Image:powershell.exe|User:Administrator|CommandLine:powershell.exe -enc JABz...|SourceIP:-|DestinationIP:-|Account:Administrator|Status:-
```

---

## Architecture

```
main.py              — Menu loop and session management
parser.py            — Log file reader and LogEvent builder
soc_engine.py        — Detection engine, MITRE mapping, IOC extraction, risk scoring
dashboard.py         — Console presentation (all views)
report_generator.py  — Incident report writer
utils.py             — Shared helpers (file I/O, JSON, formatting)
mitre_mapping.json   — MITRE ATT&CK technique definitions
config.json          — Risk thresholds, file paths, detection settings
sample_logs.txt      — Sample log data for demonstration
```

---

## Skills Demonstrated

- Security Operations Center (SOC) analysis workflow
- MITRE ATT&CK framework mapping (Tactics, Techniques, Procedures)
- Brute force and network scan pattern detection
- Indicator of Compromise (IOC) extraction
- Incident timeline correlation and attack chain analysis
- Risk scoring and severity classification
- Professional incident report generation
- Clean Python architecture without unnecessary frameworks

---

## Requirements

- Python 3.9 or higher
- No third-party packages

---

*Built for SOC Analyst portfolio and Blue Team demonstrations.*
