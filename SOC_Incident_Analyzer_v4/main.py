"""
main.py
-------
Entry point for SOC Incident Analyzer v3.0.

Owns the console menu loop only.  All analysis logic lives in
soc_engine.py; all presentation logic lives in dashboard.py and
report_generator.py.  main.py simply wires them together.
"""

import sys

import utils
import parser
import soc_engine
import dashboard
import report_generator

BANNER = r"""
  ╔══════════════════════════════════════════════════════════════════════╗
  ║        ███████╗ ██████╗  ██████╗                                    ║
  ║        ██╔════╝██╔═══██╗██╔════╝                                    ║
  ║        ███████╗██║   ██║██║                                         ║
  ║        ╚════██║██║   ██║██║                                         ║
  ║        ███████║╚██████╔╝╚██████╗                                    ║
  ║        ╚══════╝ ╚═════╝  ╚═════╝  INCIDENT ANALYZER  v3.0          ║
  ╠══════════════════════════════════════════════════════════════════════╣
  ║  Blue Team  │  MITRE ATT&CK  │  IOC Extraction  │  Risk Scoring    ║
  ╚══════════════════════════════════════════════════════════════════════╝
"""

MENU = """
  ┌─────────────────────────────────────────────────────────┐
  │  SOC INCIDENT ANALYZER v3.0  ──  MAIN MENU             │
  ├─────────────────────────────────────────────────────────┤
  │  1.  Analyze Logs                                       │
  │  2.  SOC Dashboard                                      │
  │  3.  Incident Cards                                     │
  │  4.  Attack Timeline                                    │
  │  5.  IOC Panel                                          │
  │  6.  Evidence Panel                                     │
  │  7.  Search Event ID                                    │
  │  8.  View MITRE Mapping                                 │
  │  9.  Generate Incident Report                           │
  │  10. Help                                               │
  │  11. Exit                                               │
  └─────────────────────────────────────────────────────────┘
"""

HELP_TEXT = """
  SOC INCIDENT ANALYZER v3.0 — HELP
  ────────────────────────────────────────────────────────────

  1.  Analyze Logs
      Reads sample_logs.txt, classifies every event against the MITRE
      ATT&CK mapping, runs brute-force and network-scan detections,
      extracts IOCs, and calculates the overall risk score.
      Run this FIRST before using any other option.

  2.  SOC Dashboard
      Full SOC console view: alert counts by severity, incident status,
      risk gauge, top source/destination IPs, top users and hosts,
      MITRE ATT&CK technique summary.

  3.  Incident Cards
      Displays all detected incidents with the full card layout:
      Incident ID, Technique, Tactic, Confidence, Risk Score, IPs,
      Username, Hostname, Process, Command Line, and Recommendation.

  4.  Attack Timeline
      Visual attack story showing how events chain together, grouped
      into clusters with an English assessment of the attack pattern.

  5.  IOC Panel
      All Indicators of Compromise extracted from logs and incidents:
      IPs, users, processes, hostnames, domains, hashes.

  6.  Evidence Panel
      Raw log evidence for every incident: matched rule, detection
      reason, timestamp, IOC extracted from that log line.

  7.  Search Event ID
      Look up a specific Windows/Sysmon Event ID to see its MITRE
      mapping and all related incidents.

  8.  View MITRE Mapping
      Full table of every Event ID defined in mitre_mapping.json
      with technique, tactic, and severity.

  9.  Generate Incident Report
      Writes a professional incident_report.txt with all sections:
      Executive Summary, Incident Cards, Timeline, MITRE, IOCs,
      Evidence, Risk Assessment, Recommendations, Conclusion.

  10. Help  —  This screen.

  11. Exit
"""


class AnalysisSession:
    """Holds all results from the most recent log analysis in memory."""

    def __init__(self, config):
        self.config    = config
        self.events    = []
        self.incidents = []
        self.timeline  = []
        self.stats     = None
        self.iocs      = None
        self.risk_score = 0
        self.risk_level = "N/A"
        self.mitre_map  = {}
        self.has_run    = False

    def run_analysis(self):
        paths      = self.config.get("file_paths", {})
        log_path   = paths.get("sample_logs",   "sample_logs.txt")
        mitre_path = paths.get("mitre_mapping",  "mitre_mapping.json")

        print("\n  [1/6] Reading logs...")
        self.events = parser.load_logs(log_path)
        print(f"        → {len(self.events)} log entries loaded.")

        print("  [2/6] Loading MITRE ATT&CK mapping...")
        self.mitre_map = soc_engine.load_mitre_mapping(mitre_path)

        print("  [3/6] Classifying events and detecting incidents...")
        self.incidents = soc_engine.detect_incidents(self.events, self.mitre_map, self.config)
        print(f"        → {len(self.incidents)} incidents identified.")

        print("  [4/6] Correlating attack timeline...")
        self.timeline = soc_engine.correlate_timeline(
            self.incidents, self.config.get("timeline_window_seconds", 60)
        )

        print("  [5/6] Extracting IOCs...")
        self.iocs = soc_engine.extract_iocs(self.events, self.incidents)
        ioc_total = (len(self.iocs.ip_addresses) + len(self.iocs.usernames) +
                     len(self.iocs.processes) + len(self.iocs.domains))
        print(f"        → {ioc_total} IOCs extracted.")

        print("  [6/6] Calculating risk score and building statistics...")
        self.risk_score, self.risk_level = soc_engine.calculate_risk(self.incidents, self.config)
        self.stats = soc_engine.build_summary_stats(self.events, self.incidents)
        self.has_run = True

        print()
        print(f"  ✔  Analysis complete.")
        print(f"     Risk Level : {self.risk_level}   |   Risk Score : {self.risk_score}")
        print(f"     Incidents  : {len(self.incidents)}   |   IOCs : {ioc_total}")
        print()

    def require_analysis(self):
        if not self.has_run:
            print("\n  [!] No analysis has been run yet. Choose option 1 first.\n")
            return False
        return True


def handle_search(session):
    if not session.require_analysis():
        return

    event_id = input("  Enter Event ID to search: ").strip()
    if not utils.is_valid_event_id(event_id):
        print("  [ERROR] Please enter a numeric Event ID.\n")
        return

    matches = [i for i in session.incidents if i.event_id == event_id]
    dashboard.render_search_result(event_id, matches, session.mitre_map)


def handle_generate_report(session):
    if not session.require_analysis():
        return

    output_path     = session.config.get("file_paths", {}).get("incident_report", "incident_report.txt")
    recommendations = soc_engine.build_recommendations(session.incidents)

    success = report_generator.generate_report(
        session.events,
        session.incidents,
        session.timeline,
        session.stats,
        session.risk_score,
        session.risk_level,
        recommendations,
        session.iocs,
        output_path,
    )

    if success:
        print(f"\n  ✔  Report written to: {output_path}\n")
    else:
        print("\n  [ERROR] Failed to generate the incident report.\n")


def main():
    print(BANNER)

    config  = utils.load_config("config.json")
    session = AnalysisSession(config)

    while True:
        print(MENU)
        choice = input("  Select option (1–11): ").strip()

        if choice == "1":
            session.run_analysis()

        elif choice == "2":
            if session.require_analysis():
                dashboard.render_dashboard(
                    session.stats, session.risk_score, session.risk_level, session.incidents
                )

        elif choice == "3":
            if session.require_analysis():
                dashboard.render_incident_cards(session.incidents)

        elif choice == "4":
            if session.require_analysis():
                dashboard.render_timeline(session.timeline)

        elif choice == "5":
            if session.require_analysis():
                dashboard.render_ioc_panel(session.iocs)

        elif choice == "6":
            if session.require_analysis():
                dashboard.render_evidence_panel(session.incidents)

        elif choice == "7":
            handle_search(session)

        elif choice == "8":
            if not session.mitre_map:
                print("\n  [!] MITRE mapping not loaded yet. Run option 1 first.\n")
            else:
                dashboard.render_mitre_mapping(session.mitre_map)

        elif choice == "9":
            handle_generate_report(session)

        elif choice == "10":
            print(HELP_TEXT)

        elif choice == "11":
            print("\n  Exiting SOC Incident Analyzer v3.0.  Stay secure.\n")
            sys.exit(0)

        else:
            print("\n  [!] Invalid option. Choose a number between 1 and 11.\n")


if __name__ == "__main__":
    main()
