"""
report_generator.py
--------------------
Generates a professional SOC Incident Report (incident_report.txt).

Report sections:
    1.  Header & Metadata
    2.  Executive Summary
    3.  Investigation Overview
    4.  Attack Narrative
    5.  Attack Timeline
    6.  Incident Summary (all incident cards)
    7.  MITRE ATT&CK Mapping
    8.  Indicators of Compromise
    9.  Evidence Collected
   10.  Risk Assessment
   11.  Containment Actions
   12.  Eradication Actions
   13.  Recovery Actions
   14.  Lessons Learned
   15.  Recommendations
   16.  Conclusion

No analysis is performed here — only formatting and writing.
"""

from datetime import datetime

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
W = 70  # report line width


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _line(char="─"):
    return char * W


def _center(text, char="═"):
    return text.center(W, char)


def _section(title):
    return ["", _line("═"), f"  {title.upper()}", _line("─")]


def _subsection(title):
    return ["", f"  ── {title} " + "─" * max(0, W - len(title) - 6)]


def _field(label, value, width=24):
    return f"  {label:<{width}}: {value}"


def _wrap(text, indent="  ", max_len=W):
    """Wraps text at word boundaries to fit within max_len."""
    words = text.split()
    lines = []
    line  = indent
    for word in words:
        if len(line) + len(word) + 1 > max_len:
            lines.append(line)
            line = indent + word
        else:
            line += (" " if line != indent else "") + word
    if line.strip():
        lines.append(line)
    return lines


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_header(stats, risk_score, risk_level):
    return [
        _center("", "═"),
        _center("  SOC INCIDENT ANALYZER v3.0  ──  INCIDENT REPORT  "),
        _center("  CONFIDENTIAL – FOR AUTHORIZED SOC PERSONNEL ONLY  "),
        _center("", "═"),
        "",
        _field("Report Generated",    datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        _field("Prepared By",         "SOC Incident Analyzer v3.0 (Automated)"),
        _field("Classification",      "CONFIDENTIAL"),
        _field("Logs Processed",      stats.get("logs_processed", 0)),
        _field("Incidents Detected",  stats.get("incidents_detected", 0)),
        _field("Overall Risk Level",  risk_level),
        _field("Overall Risk Score",  f"{risk_score}/100"),
        _field("Highest Severity",    stats.get("highest_severity", "N/A")),
        _line(),
    ]


def _build_executive_summary(stats, risk_score, risk_level, incidents):
    lines  = _section("1. Executive Summary")
    sev    = stats.get("severity_counts", {})
    crit   = sev.get("Critical", 0)
    high   = sev.get("High", 0)
    med    = sev.get("Medium", 0)
    low    = sev.get("Low", 0)
    total  = stats.get("incidents_detected", 0)
    cats   = stats.get("attack_categories", [])

    lines += _wrap(
        f"This investigation analysed {stats.get('logs_processed', 0)} log entries from Windows "
        f"and Sysmon sources. The analysis identified {total} security incident(s) spanning "
        f"{len(cats)} attack category/categories. The highest severity observed was "
        f"'{stats.get('highest_severity', 'N/A')}'. The environment's overall risk score is "
        f"{risk_score}/100, placing it at {risk_level} risk level."
    )
    lines += [
        "",
        "  Severity Distribution:",
        f"    Critical : {crit}",
        f"    High     : {high}",
        f"    Medium   : {med}",
        f"    Low      : {low}",
        f"    Total    : {total}",
        "",
        f"  Attack Categories Detected:",
    ]
    for cat in cats:
        lines.append(f"    ● {cat}")

    lines += ["", _line()]
    return lines


def _build_investigation_overview(stats, incidents):
    lines = _section("2. Investigation Overview")
    lines += [
        "",
        "  Scope:",
        "    ● Log sources analysed : Windows Event Log, Sysmon",
        f"   ● Total log entries    : {stats.get('logs_processed', 0)}",
        f"   ● Total incidents      : {stats.get('incidents_detected', 0)}",
        "",
        "  MITRE ATT&CK Techniques Observed:",
    ]

    mitre_detail = stats.get("mitre_detail", {})
    if mitre_detail:
        for tid, info in sorted(mitre_detail.items()):
            lines.append(f"    ● {tid:<14} {info['name']:<30} ({info['count']} event(s))")
    else:
        lines.append("    None mapped.")

    lines += [
        "",
        "  Incident Status Summary:",
        f"    Open         : {sum(1 for i in incidents if i.status == 'OPEN')}",
        f"    Investigating: {sum(1 for i in incidents if i.status == 'INVESTIGATING')}",
        f"    Closed       : {sum(1 for i in incidents if i.status == 'CLOSED')}",
        "",
        _line(),
    ]
    return lines


def _build_attack_narrative(incidents, timeline):
    """
    Builds a plain-English attack narrative describing the full kill chain
    based on the detected incidents and timeline clusters.
    """
    lines = _section("3. Attack Narrative")
    lines += [
        "",
        "  The following narrative describes the attack story as reconstructed",
        "  from correlated log evidence.",
        "",
    ]

    categories = {i.category for i in incidents}
    narrative  = []

    if "Network Reconnaissance" in categories:
        recon = next((i for i in incidents if i.category == "Network Reconnaissance"), None)
        if recon:
            narrative.append(
                f"  [Reconnaissance] At {recon.timestamp}, a network scan was detected "
                f"from {recon.source_ip}. The attacker probed {recon.event_count} "
                f"host(s) to map the environment."
            )

    if "Credential Access" in categories:
        bf = next((i for i in incidents if i.category == "Credential Access"), None)
        if bf:
            narrative.append(
                f"  [Credential Attack] At {bf.timestamp}, {bf.event_count} failed "
                f"authentication attempts were recorded for account '{bf.username}' "
                f"from {bf.source_ip}. This is consistent with brute force (T1110)."
            )

    if "Authentication Success" in categories:
        success = next((i for i in incidents if i.category == "Authentication Success"), None)
        if success:
            narrative.append(
                f"  [Initial Access] At {success.timestamp}, account '{success.username}' "
                f"successfully authenticated from {success.source_ip}. Following prior "
                f"failed attempts, this may represent account compromise."
            )

    if "Process Creation" in categories:
        procs = [i for i in incidents if i.category == "Process Creation"]
        for p in procs[:3]:
            if p.severity in ("High", "Critical"):
                narrative.append(
                    f"  [Execution] At {p.timestamp}, '{p.process}' was executed by "
                    f"'{p.username}'. Technique: {p.technique_id} ({p.technique_name}). "
                    f"Severity: {p.severity}."
                )

    if "Network Connection" in categories:
        conn = next(
            (i for i in incidents if i.category == "Network Connection"
             and i.severity in ("High", "Critical")), None
        )
        if conn:
            narrative.append(
                f"  [C2 Callback] At {conn.timestamp}, '{conn.process}' established "
                f"an outbound connection to {conn.dest_ip}. This is indicative of a "
                f"Command and Control (C2) callback ({conn.technique_id})."
            )

    if "Image Loaded" in categories:
        img = next((i for i in incidents if i.category == "Image Loaded"), None)
        if img:
            narrative.append(
                f"  [Defense Evasion] At {img.timestamp}, a suspicious DLL/image "
                f"('{img.process}') was loaded. This may indicate DLL injection or "
                f"process hollowing ({img.technique_id})."
            )

    if not narrative:
        narrative.append("  Insufficient correlated events to construct a full attack narrative.")

    lines += narrative
    if timeline:
        cluster_labels = [c["chain_label"] for c in timeline]
        lines += [
            "",
            "  Timeline Chain Assessment:",
        ]
        for idx, label in enumerate(cluster_labels, 1):
            lines.append(f"    Cluster {idx}: {label}")

    lines += ["", _line()]
    return lines


def _build_timeline(timeline):
    lines = _section("4. Attack Timeline")

    if not timeline:
        lines += ["  No timeline data available.", _line()]
        return lines

    for idx, cluster in enumerate(timeline, start=1):
        entries     = cluster["entries"]
        chain_label = cluster["chain_label"]
        lines += [
            "",
            f"  Cluster {idx}: {chain_label}",
            f"  {'─'*60}",
        ]
        prev_category = None
        for inc in entries:
            if inc.category != prev_category:
                lines.append(f"  [{inc.category}]")
                prev_category = inc.category
            lines.append(f"    {inc.timestamp}  →  {inc.technique_name}  [{inc.severity}]")
            if inc.source_ip != "-":
                lines.append(f"       src: {inc.source_ip}  →  dst: {inc.dest_ip}  user: {inc.username}")
            if inc.command_line not in ("-", ""):
                lines.append(f"       cmd: {inc.command_line[:70]}")
        lines += ["", f"  Assessment: {chain_label}"]

    lines += ["", _line()]
    return lines


def _build_incident_summary(incidents):
    lines = _section("5. Incident Summary")

    if not incidents:
        lines += ["  No incidents were detected.", _line()]
        return lines

    for inc in incidents:
        lines += [
            "",
            f"  {inc.incident_id}  [{inc.severity.upper()}]  {inc.timestamp}",
            f"  {'─'*60}",
            f"  Technique   : {inc.technique_id} – {inc.technique_name}",
            f"  Tactic      : {inc.tactic}",
            f"  Category    : {inc.category}",
            f"  Confidence  : {inc.confidence}%",
            f"  Risk Score  : {inc.risk_score}/100",
            f"  Status      : {inc.status}",
            f"  Event Count : {inc.event_count}",
            f"  Source IP   : {inc.source_ip}",
            f"  Dest IP     : {inc.dest_ip}",
            f"  Username    : {inc.username}",
            f"  Process     : {inc.process}",
        ]
        if inc.command_line not in ("-", ""):
            lines.append(f"  Command     : {inc.command_line[:70]}")
        lines += [""]
        lines += _wrap(f"  Description: {inc.description}")
        lines += _wrap(f"  Rec: {inc.recommendation}")

    lines += ["", _line()]
    return lines


def _build_mitre_section(stats, incidents):
    from soc_engine import TECHNIQUE_TACTICS, TECHNIQUE_DESCRIPTIONS

    lines        = _section("6. MITRE ATT&CK Mapping")
    mitre_detail = stats.get("mitre_detail", {})

    if not mitre_detail:
        lines += ["  No MITRE techniques were mapped.", _line()]
        return lines

    for tech_id, info in sorted(mitre_detail.items()):
        desc = TECHNIQUE_DESCRIPTIONS.get(tech_id, "No description available.")
        lines += [
            "",
            f"  Technique  : {tech_id} – {info['name']}",
            f"  Tactic     : {info['tactic']}",
            f"  Count      : {info['count']} incident(s)",
        ]
        lines += _wrap(f"  Description: {desc}")

    lines += ["", _line()]
    return lines


def _build_ioc_section(iocs):
    lines = _section("7. Indicators of Compromise (IOC)")

    total = (len(iocs.ip_addresses) + len(iocs.usernames) + len(iocs.processes) +
             len(iocs.hostnames) + len(iocs.domains) + len(iocs.hashes))
    lines.append(f"\n  Total IOCs: {total}")

    for title, items in [
        ("IP ADDRESSES", iocs.ip_addresses),
        ("USERS",        iocs.usernames),
        ("PROCESSES",    iocs.processes),
        ("HOSTNAMES",    iocs.hostnames),
        ("DOMAINS",      iocs.domains),
        ("HASHES",       iocs.hashes),
    ]:
        lines += ["", f"  {title} [{len(items)}]:"]
        if items:
            for item in items:
                lines.append(f"    ● {item}")
        else:
            lines.append("    None detected.")

    if iocs.commands:
        lines += ["", f"  SUSPICIOUS COMMAND LINES [{len(iocs.commands)}]:"]
        for cmd in iocs.commands[:5]:
            lines.append(f"    ● {cmd[:75]}")

    lines += ["", _line()]
    return lines


def _build_evidence_section(incidents):
    lines = _section("8. Evidence Collected")

    for inc in incidents:
        if not inc.evidence:
            continue
        lines += [
            "",
            f"  {inc.incident_id}  [{inc.severity}]  {inc.technique_name}",
        ]
        for ev_idx, ev in enumerate(inc.evidence, start=1):
            lines += [
                f"    Evidence #{ev_idx}",
                f"      Timestamp     : {ev.get('timestamp', '-')}",
                f"      Event ID      : {ev.get('event_id', '-')}",
                f"      MITRE         : {ev.get('mitre_technique', '-')}",
                f"      Matched Rule  : {ev.get('matched_rule', '-')}",
                f"      IOC           : {ev.get('ioc', 'None')}",
            ]
            lines += _wrap(f"      Reason        : {ev.get('reason', '-')}", indent="      ")
            raw = ev.get("raw_log", "-")
            lines.append(f"      Raw Log       : {raw[:75]}")

    lines += ["", _line()]
    return lines


def _build_risk_section(risk_score, risk_level, incidents):
    lines = _section("9. Risk Assessment")

    bar_width = 40
    filled    = int((min(risk_score, 100) / 100) * bar_width)
    bar       = "█" * filled + "░" * (bar_width - filled)

    avg_inc_risk = (
        int(sum(i.risk_score for i in incidents) / max(len(incidents), 1))
        if incidents else 0
    )

    lines += [
        "",
        f"  Overall Risk Score : {risk_score}/100",
        f"  Risk Level         : {risk_level}",
        f"  Gauge              : [{bar}]",
        f"  Avg Incident Score : {avg_inc_risk}/100",
        "",
        "  Risk Score Methodology:",
        "    Each incident score (0–100) is calculated from:",
        "      ● Severity weight      (max 60 pts)",
        "      ● Confidence factor    (scales base score)",
        "      ● IOC/evidence count   (max 20 pts)",
        "      ● MITRE mapping        (max 10 pts)",
        "      ● Indicator signals    (max 10 pts)",
        "    Organisation score = weighted average × breadth factor (capped at 100).",
        "",
        "  Risk Level Thresholds:",
        "    LOW      (0–25):   Minimal activity; routine monitoring.",
        "    MEDIUM  (26–50):   Moderate activity; investigate priority alerts.",
        "    HIGH    (51–75):   Significant activity; immediate triage required.",
        "    CRITICAL (76–100): Active attack likely; escalate now.",
        "",
        _line(),
    ]
    return lines


def _build_containment_section(incidents):
    lines = _section("10. Containment Actions")
    lines += ["", "  Immediate containment steps based on detected incidents:", ""]

    actions = []
    cats = {i.category for i in incidents}
    sevs = {i.severity for i in incidents}

    if "Critical" in sevs or "High" in sevs:
        actions.append("  1. ISOLATE the affected host(s) from the network immediately.")
        actions.append("     Remove network cable or quarantine via EDR/NAC.")
    if "Credential Access" in cats or "Authentication Success" in cats:
        actions.append("  2. LOCK or RESET all compromised accounts.")
        actions.append("     Disable the targeted account(s) pending investigation.")
        actions.append("  3. BLOCK the identified source IP(s) at the perimeter firewall.")
    if "Network Connection" in cats:
        actions.append("  4. BLOCK the identified external destination IP(s) at the firewall.")
        actions.append("     Update IDS/IPS signatures for identified C2 indicators.")
    if "Process Creation" in cats:
        actions.append("  5. TERMINATE any malicious processes still running.")
        actions.append("     Identify and suspend related scheduled tasks.")
    if not actions:
        actions.append("  ● No specific containment actions identified for current incidents.")

    lines += actions
    lines += ["", _line()]
    return lines


def _build_eradication_section(incidents):
    lines = _section("11. Eradication Actions")
    lines += ["", "  Steps to remove attacker presence from the environment:", ""]

    eradication = [
        "  1. SCAN the affected host(s) with an up-to-date antivirus/EDR solution.",
        "  2. REVIEW and REMOVE any persistence mechanisms:",
        "     ● Registry Run keys (HKCU/HKLM\\...\\CurrentVersion\\Run)",
        "     ● Scheduled tasks, services, or startup folder entries.",
        "  3. REMOVE any malicious files or tools dropped by the attacker.",
        "     Hash and preserve copies for forensic evidence before deletion.",
        "  4. PATCH any vulnerabilities exploited during the incident.",
        "  5. RESET all potentially compromised credentials including service accounts.",
        "  6. REVIEW and REVOKE any access tokens or sessions established by the attacker.",
    ]

    lines += eradication
    lines += ["", _line()]
    return lines


def _build_recovery_section():
    lines = _section("12. Recovery Actions")
    lines += ["", "  Steps to restore operations safely:", ""]

    recovery = [
        "  1. VERIFY the affected system is clean before returning to production.",
        "     Obtain sign-off from the SOC team lead or IR manager.",
        "  2. RESTORE from a clean backup if system integrity is uncertain.",
        "  3. MONITOR the affected host(s) closely for 72 hours post-recovery.",
        "  4. RE-ENABLE affected accounts only after credentials have been reset.",
        "  5. VALIDATE security controls are functioning correctly (firewall, EDR, logging).",
        "  6. COMMUNICATE recovery status to affected stakeholders.",
    ]

    lines += recovery
    lines += ["", _line()]
    return lines


def _build_lessons_learned(incidents, risk_level):
    lines = _section("13. Lessons Learned")
    lines += ["", "  Key observations from this investigation:", ""]

    categories = {i.category for i in incidents}
    lessons    = []

    if "Network Reconnaissance" in categories:
        lessons.append(
            "  ● Network scanning was detected. Review IDS/IPS rules to alert on "
            "rapid connection attempts. Consider network segmentation."
        )
    if "Credential Access" in categories:
        lessons.append(
            "  ● Brute force activity was observed. Enforce account lockout policy "
            "(5 failures / 15-minute window) and enable MFA on all accounts."
        )
    if "Authentication Success" in categories:
        lessons.append(
            "  ● A successful logon followed credential attack activity. "
            "Implement privileged access workstations (PAW) for admin accounts."
        )
    if "Process Creation" in categories:
        lessons.append(
            "  ● Suspicious process execution was detected. Implement application "
            "whitelisting or AppLocker policies to restrict unauthorised execution."
        )
    if "Network Connection" in categories:
        lessons.append(
            "  ● Outbound connections to external IPs were detected. Enforce "
            "egress filtering and proxy inspection for all outbound web traffic."
        )
    if risk_level in ("HIGH", "CRITICAL"):
        lessons.append(
            "  ● The high risk level suggests insufficient detection capability. "
            "Review SIEM alert thresholds and ensure all endpoints are enrolled in EDR."
        )

    if not lessons:
        lessons.append("  ● Conduct a post-incident review meeting within 48 hours.")

    lines += lessons
    lines += ["", _line()]
    return lines


def _build_recommendations_section(recommendations):
    lines = _section("14. Recommendations")
    lines += [""]

    if not recommendations:
        lines += ["  No specific recommendations at this time."]
    else:
        for idx, rec in enumerate(recommendations, start=1):
            lines += _wrap(f"  {idx}. {rec}")
            lines.append("")

    lines += [_line()]
    return lines


def _build_conclusion(risk_level, incidents):
    lines = _section("15. Conclusion")

    crit_count = sum(1 for i in incidents if i.severity == "Critical")
    high_count = sum(1 for i in incidents if i.severity == "High")
    cats       = sorted({i.category for i in incidents})

    lines += [
        "",
        *_wrap(
            f"This investigation identified {len(incidents)} security incident(s), "
            f"including {crit_count} Critical and {high_count} High severity events. "
            f"Attack activity spanned the following categories: "
            f"{', '.join(cats) if cats else 'None'}. "
            f"The overall environment risk level is assessed as {risk_level}."
        ),
        "",
        *_wrap(
            "All containment, eradication, and recovery actions listed in this report "
            "should be actioned and prioritised according to incident severity. "
            "High and Critical incidents should be escalated to Tier-2 immediately."
        ),
        "",
        *_wrap(
            "This report was generated automatically by SOC Incident Analyzer v3.0. "
            "It must be reviewed by a qualified SOC analyst before distribution. "
            "Preserve all evidence and log files for potential legal proceedings."
        ),
        "",
        _line(),
    ]
    return lines


# ---------------------------------------------------------------------------
# Main report entry point
# ---------------------------------------------------------------------------

def generate_report(events, incidents, timeline, stats, risk_score, risk_level,
                    recommendations, iocs, output_path="incident_report.txt"):
    """
    Assembles and writes the full SOC Incident Report.
    Returns True on success, False if the file could not be written.
    """
    lines = []
    lines += _build_header(stats, risk_score, risk_level)
    lines += _build_executive_summary(stats, risk_score, risk_level, incidents)
    lines += _build_investigation_overview(stats, incidents)
    lines += _build_attack_narrative(incidents, timeline)
    lines += _build_timeline(timeline)
    lines += _build_incident_summary(incidents)
    lines += _build_mitre_section(stats, incidents)
    lines += _build_ioc_section(iocs)
    lines += _build_evidence_section(incidents)
    lines += _build_risk_section(risk_score, risk_level, incidents)
    lines += _build_containment_section(incidents)
    lines += _build_eradication_section(incidents)
    lines += _build_recovery_section()
    lines += _build_lessons_learned(incidents, risk_level)
    lines += _build_recommendations_section(recommendations)
    lines += _build_conclusion(risk_level, incidents)

    lines += [
        "",
        _center("  END OF REPORT  "),
        _center("", "═"),
    ]

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return True
    except (IOError, OSError) as e:
        print(f"[ERROR] Could not write report to '{output_path}': {e}")
        return False
