"""
dashboard.py
------------
Console presentation layer for SOC Incident Analyzer v3.0.

All methods receive pre-computed data from soc_engine.py.
No analysis is performed here — only formatting and printing.

Improvements in this version:
    - Cleaner, professional ASCII dashboard layout
    - Top Processes shown in dashboard
    - Investigation Status with open/investigating/closed breakdown
    - Smarter incident cards: benign / suspicious / malicious classification
    - Attack timeline with SOC phase labels
    - Evidence panel with full forensic detail (EventID, MITRE technique, reason)
    - Enhanced search result with SOC investigation guidance
    - IOC panel with category totals
"""

import os
from soc_engine import SEVERITY_ORDER, ATTACK_PHASES


# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

def _supports_color():
    """Returns True if the terminal supports ANSI escape codes."""
    if os.name == "nt":
        try:
            import ctypes
            kernel = ctypes.windll.kernel32
            kernel.SetConsoleMode(kernel.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return True


USE_COLOR = _supports_color()


class C:
    """ANSI colour constants — disabled gracefully when terminal lacks support."""
    RESET  = "\033[0m"  if USE_COLOR else ""
    BOLD   = "\033[1m"  if USE_COLOR else ""
    DIM    = "\033[2m"  if USE_COLOR else ""
    RED    = "\033[91m" if USE_COLOR else ""
    ORANGE = "\033[33m" if USE_COLOR else ""
    YELLOW = "\033[93m" if USE_COLOR else ""
    GREEN  = "\033[92m" if USE_COLOR else ""
    CYAN   = "\033[96m" if USE_COLOR else ""
    BLUE   = "\033[94m" if USE_COLOR else ""
    WHITE  = "\033[97m" if USE_COLOR else ""
    GREY   = "\033[90m" if USE_COLOR else ""


SEVERITY_COLOR = {
    "Critical": C.RED,
    "High":     C.ORANGE,
    "Medium":   C.YELLOW,
    "Low":      C.GREEN,
}

RISK_COLOR = {
    "CRITICAL": C.RED,
    "HIGH":     C.ORANGE,
    "MEDIUM":   C.YELLOW,
    "LOW":      C.GREEN,
}


def _sev(text, severity):
    """Formats text with severity colour."""
    color = SEVERITY_COLOR.get(severity, "")
    return f"{C.BOLD}{color}{text}{C.RESET}"


def _risk(text, level):
    """Formats text with risk-level colour."""
    color = RISK_COLOR.get(level.upper(), "")
    return f"{C.BOLD}{color}{text}{C.RESET}"


def _col(text, color):
    """Applies an arbitrary colour to text."""
    return f"{color}{text}{C.RESET}"


# ---------------------------------------------------------------------------
# Layout constants and helpers
# ---------------------------------------------------------------------------

WIDTH = 72   # console width for all panels


def _header(title):
    """Prints a section header bar."""
    print()
    print(_col("=" * WIDTH, C.CYAN))
    print(_col(f"  {title}", C.BOLD + C.WHITE))
    print(_col("=" * WIDTH, C.CYAN))


def _section(title):
    """Prints a sub-section opening line."""
    pad = max(0, WIDTH - len(title) - 6)
    print()
    print(_col(f"  ┌─ {title} ", C.CYAN) + _col("─" * pad, C.GREY))


def _row(label, value, color=None):
    """Prints a labelled key-value row inside a section box."""
    val_str = f"{color}{value}{C.RESET}" if color else str(value)
    print(f"  │  {C.GREY}{label:<24}{C.RESET}{val_str}")


def _divider():
    """Prints the closing line of a section box."""
    print(_col("  └" + "─" * (WIDTH - 3), C.GREY))


def _blank():
    print()


def _wrap_text(text, indent="  │    ", max_len=WIDTH):
    """Word-wraps text to fit within the panel width."""
    words = text.split()
    line  = indent
    lines = []
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
# Risk gauge bar
# ---------------------------------------------------------------------------

def _risk_bar(score, max_score=100):
    """Renders a 40-char progress bar for the risk score (0–100)."""
    bar_width = 40
    filled    = int((min(score, max_score) / max_score) * bar_width)
    filled    = max(0, min(filled, bar_width))
    empty     = bar_width - filled

    if score > 75:
        bar_color = C.RED
    elif score > 50:
        bar_color = C.ORANGE
    elif score > 25:
        bar_color = C.YELLOW
    else:
        bar_color = C.GREEN

    bar = bar_color + "█" * filled + C.GREY + "░" * empty + C.RESET
    return bar


# ---------------------------------------------------------------------------
# Incident classification helper
# ---------------------------------------------------------------------------

def _classify_disposition(inc):
    """
    Returns a human-readable disposition label for an incident card.
    Differentiates Benign / Suspicious / Malicious based on severity and context.
    """
    sev = inc.severity
    cmd = (inc.command_line or "-").lower()
    proc = (inc.process or "-").lower()

    benign_procs = {"explorer.exe", "svchost.exe", "taskhostw.exe", "sihost.exe"}

    if proc in benign_procs:
        return ("BENIGN",    C.GREEN)
    if sev == "Critical":
        return ("MALICIOUS", C.RED)
    if sev == "High":
        if any(flag in cmd for flag in ["-enc", "-nop", "hidden", "bypass", "iex"]):
            return ("MALICIOUS", C.RED)
        return ("SUSPICIOUS", C.ORANGE)
    if sev == "Medium":
        return ("SUSPICIOUS", C.YELLOW)
    return ("BENIGN",    C.GREEN)


# ---------------------------------------------------------------------------
# SOC Dashboard  (option 2)
# ---------------------------------------------------------------------------

def render_dashboard(stats, risk_score, risk_level, incidents=None):
    """Renders the full SOC console dashboard."""
    incidents = incidents or []
    sev       = stats.get("severity_counts", {})
    total     = stats.get("incidents_detected", 0)

    _header("SOC INCIDENT ANALYZER v3.0  ──  LIVE DASHBOARD")

    # ── Alert Summary ─────────────────────────────────────────────────────
    _section("ALERT SUMMARY")
    crit = sev.get("Critical", 0)
    high = sev.get("High", 0)
    med  = sev.get("Medium", 0)
    low  = sev.get("Low", 0)

    print(f"  │")
    print(
        f"  │  "
        f"{_sev('● CRITICAL', 'Critical')} {C.BOLD}{crit:>4}{C.RESET}   "
        f"{_sev('● HIGH', 'High')}     {C.BOLD}{high:>4}{C.RESET}   "
        f"{_sev('● MEDIUM', 'Medium')} {C.BOLD}{med:>4}{C.RESET}   "
        f"{_sev('● LOW', 'Low')}      {C.BOLD}{low:>4}{C.RESET}"
    )
    print(f"  │")
    _divider()

    # ── Investigation Status ──────────────────────────────────────────────
    _section("INVESTIGATION STATUS")
    open_count   = sum(1 for i in incidents if i.status == "OPEN")
    inv_count    = sum(1 for i in incidents if i.status == "INVESTIGATING")
    closed_count = sum(1 for i in incidents if i.status == "CLOSED")

    _row("Open Incidents",   open_count,   C.RED)
    _row("Investigating",    inv_count,    C.YELLOW)
    _row("Closed",           closed_count, C.GREEN)
    _row("Total Incidents",  total,        C.WHITE)
    _row("Events Processed", stats.get("logs_processed", 0), C.CYAN)
    _divider()

    # ── Risk Assessment ───────────────────────────────────────────────────
    _section("RISK ASSESSMENT")
    bar = _risk_bar(risk_score)
    print(f"  │  {bar}  {_risk(risk_level, risk_level)}  ({risk_score}/100)")
    print(f"  │")

    detection_rate = stats.get("detection_rate", 0)
    avg_risk = (
        int(sum(i.risk_score for i in incidents) / max(len(incidents), 1))
        if incidents else 0
    )
    _row("Detection Rate",    f"{detection_rate}%",  C.CYAN)
    _row("Avg Incident Risk", f"{avg_risk}/100",     C.CYAN)
    _row("Highest Severity",
         stats.get("highest_severity", "N/A"),
         SEVERITY_COLOR.get(stats.get("highest_severity", ""), C.WHITE))
    _divider()

    # ── Top Network Indicators ────────────────────────────────────────────
    _section("TOP NETWORK INDICATORS")
    src_ips = stats.get("top_src_ips", [])
    dst_ips = stats.get("top_dst_ips", [])

    print(f"  │  {C.BOLD}{'Source IP':<24} Hits   {'Destination IP':<24} Hits{C.RESET}")
    print(f"  │  {'─'*24} ────   {'─'*24} ────")
    for r in range(min(max(len(src_ips), len(dst_ips), 1), 5)):
        s = f"{src_ips[r][0]:<24} {src_ips[r][1]:<5}" if r < len(src_ips) else " " * 30
        d = f"{dst_ips[r][0]:<24} {dst_ips[r][1]:<5}" if r < len(dst_ips) else ""
        print(f"  │  {C.YELLOW}{s}{C.RESET}  {C.CYAN}{d}{C.RESET}")
    _divider()

    # ── Top Users & Processes ─────────────────────────────────────────────
    _section("TOP USERS & PROCESSES INVOLVED")
    users = stats.get("top_users",    [])
    procs = stats.get("top_processes", [])
    print(f"  │  {C.BOLD}{'User':<24} Hits   {'Process':<24} Hits{C.RESET}")
    print(f"  │  {'─'*24} ────   {'─'*24} ────")
    for r in range(min(max(len(users), len(procs), 1), 5)):
        u = f"{users[r][0]:<24} {users[r][1]:<5}" if r < len(users) else " " * 30
        p = f"{procs[r][0]:<24} {procs[r][1]:<5}" if r < len(procs) else ""
        print(f"  │  {C.CYAN}{u}{C.RESET}  {C.GREY}{p}{C.RESET}")
    _divider()

    # ── MITRE ATT&CK Summary ──────────────────────────────────────────────
    _section("MITRE ATT&CK SUMMARY")
    mitre_detail = stats.get("mitre_detail", {})
    if mitre_detail:
        print(f"  │  {C.BOLD}{'Technique':<14} {'Tactic':<26} {'Name':<22} Hits{C.RESET}")
        print(f"  │  {'─'*14} {'─'*26} {'─'*22} ────")
        for tid, info in sorted(mitre_detail.items()):
            print(
                f"  │  {C.CYAN}{tid:<14}{C.RESET}"
                f"{C.GREY}{info['tactic'][:24]:<26}{C.RESET}"
                f"{info['name'][:20]:<22}"
                f"{C.YELLOW}{info['count']}{C.RESET}"
            )
    else:
        print(f"  │  {C.GREY}No MITRE techniques mapped.{C.RESET}")
    _divider()

    # ── Recent Activity ───────────────────────────────────────────────────
    if incidents:
        _section("RECENT ACTIVITY")
        recent = sorted(incidents, key=lambda i: i.timestamp, reverse=True)[:3]
        for inc in recent:
            sev_color = SEVERITY_COLOR.get(inc.severity, C.WHITE)
            print(
                f"  │  {C.GREY}{inc.timestamp}{C.RESET}  "
                f"{sev_color}[{inc.severity:<8}]{C.RESET}  "
                f"{C.CYAN}{inc.incident_id}{C.RESET}  "
                f"{inc.technique_name[:28]}"
            )
        _divider()

    print()


# ---------------------------------------------------------------------------
# Incident Cards  (option 3)
# ---------------------------------------------------------------------------

def render_incident_cards(incidents):
    """Renders detailed incident cards for all detected incidents."""
    _header("INCIDENT CARDS  ──  All Detected Incidents")

    if not incidents:
        print(f"\n  {C.GREY}No incidents to display. Run option 1 first.{C.RESET}\n")
        return

    for inc in incidents:
        sev_color               = SEVERITY_COLOR.get(inc.severity, C.WHITE)
        disposition, disp_color = _classify_disposition(inc)

        print()
        print(_col("  ┌" + "─" * (WIDTH - 3), C.CYAN))
        print(
            f"  │  {C.BOLD}{C.WHITE}{inc.incident_id}{C.RESET}"
            f"  {sev_color}[{inc.severity.upper()}]{C.RESET}"
            f"  {C.BOLD}{disp_color}[{disposition}]{C.RESET}"
            f"  {C.GREY}{inc.timestamp}{C.RESET}"
        )
        print(_col("  ├" + "─" * (WIDTH - 3), C.GREY))

        # Classification fields
        _row("Technique",      f"{inc.technique_id} – {inc.technique_name}", C.CYAN)
        _row("Tactic",         inc.tactic,      C.BLUE)
        _row("Category",       inc.category,    C.WHITE)
        _row("Confidence",     f"{inc.confidence}%",  C.WHITE)
        _row("Risk Score",     f"{inc.risk_score}/100", C.YELLOW)
        _row("Status",         inc.status,      C.GREEN)
        _row("Event Count",    inc.event_count, C.GREY)
        print(f"  │")

        # Host / network context
        _row("Source IP",      inc.source_ip,   C.YELLOW)
        _row("Destination IP", inc.dest_ip,     C.CYAN)
        _row("Username",       inc.username,    C.WHITE)
        _row("Hostname",       inc.hostname,    C.GREY)
        _row("Process",        inc.process,     C.WHITE)
        _row("Parent Process", inc.parent_process, C.GREY)

        if inc.command_line and inc.command_line != "-":
            cmd = (inc.command_line[:60] + "…") if len(inc.command_line) > 60 else inc.command_line
            _row("Command Line", cmd, C.GREY)
        print(f"  │")

        # Description (word-wrapped)
        for line in _wrap_text(inc.description):
            print(_col(line, C.GREY))
        print(f"  │")

        # SOC Recommendation (word-wrapped)
        rec_lines = _wrap_text(f"Rec: {inc.recommendation}", indent="  │  ")
        for line in rec_lines:
            print(_col(line, C.YELLOW))

        print(_col("  └" + "─" * (WIDTH - 3), C.GREY))

    print()


# ---------------------------------------------------------------------------
# Attack Timeline  (option 4)
# ---------------------------------------------------------------------------

STAGE_ICONS = {
    "Network Reconnaissance": "🔍",
    "Credential Access":      "🔑",
    "Authentication Success": "✅",
    "Authentication Failure": "❌",
    "Process Creation":       "⚙️ ",
    "Network Connection":     "🌐",
    "Image Loaded":           "💉",
    "Unmapped Event":         "❓",
}

# Maps incident categories to SOC attack phases
CATEGORY_TO_PHASE = {
    "Network Reconnaissance": "Reconnaissance",
    "Authentication Failure": "Initial Access",
    "Credential Access":      "Initial Access",
    "Authentication Success": "Initial Access",
    "Process Creation":       "Execution",
    "Network Connection":     "Command & Control",
    "Image Loaded":           "Defense Evasion",
}


def render_timeline(timeline):
    """Renders a visual attack story timeline with SOC phase labels."""
    _header("ATTACK TIMELINE  ──  Incident Narrative")

    if not timeline:
        print(f"\n  {C.GREY}No timeline data. Run option 1 first.{C.RESET}\n")
        return

    for cluster_idx, cluster in enumerate(timeline, start=1):
        entries     = cluster["entries"]
        chain_label = cluster["chain_label"]
        start_time  = entries[0].timestamp if entries else "-"
        end_time    = entries[-1].timestamp if entries else "-"
        severities  = [i.severity for i in entries]
        highest_sev = next(
            (s for s in reversed(SEVERITY_ORDER) if s in severities), "Low"
        )

        print()
        pad = max(0, WIDTH - len(chain_label) - 16)
        print(_col(f"  ╔══ Cluster {cluster_idx}  ({'═'*pad}╗", C.CYAN))
        print(_col(f"  ║  {chain_label}", C.BOLD + C.WHITE))
        print(_col(f"  ║  {start_time}  →  {end_time}  │  "
                   f"Highest: {highest_sev}", C.GREY))
        print(_col(f"  ╚{'═'*(WIDTH-4)}╝", C.CYAN))
        print()

        prev_phase = None
        for idx, inc in enumerate(entries):
            icon      = STAGE_ICONS.get(inc.category, "◈")
            sev_color = SEVERITY_COLOR.get(inc.severity, C.WHITE)
            phase     = CATEGORY_TO_PHASE.get(inc.category, inc.category)

            # Print phase banner when the attack phase changes
            if phase != prev_phase:
                print(
                    f"  {C.CYAN}{'─'*4} {C.BOLD}{C.WHITE}PHASE: {phase.upper()}{C.RESET}"
                    f" {C.CYAN}{'─'*max(0, WIDTH - len(phase) - 14)}{C.RESET}"
                )
            prev_phase = phase

            print(
                f"  {C.GREY}{inc.timestamp}{C.RESET}  {icon}  "
                f"{C.BOLD}{inc.technique_name}{C.RESET}  "
                f"{sev_color}[{inc.severity}]{C.RESET}"
            )

            if inc.source_ip != "-":
                print(
                    f"         {C.GREY}src:{inc.source_ip}  →  "
                    f"dst:{inc.dest_ip}  user:{inc.username}{C.RESET}"
                )
            if inc.command_line not in ("-", ""):
                cmd = (inc.command_line[:68] + "…") if len(inc.command_line) > 68 else inc.command_line
                print(f"         {C.GREY}cmd: {cmd}{C.RESET}")

            if idx < len(entries) - 1:
                print(f"              {C.CYAN}↓{C.RESET}")

        print()
        print(f"  {C.BOLD}{C.YELLOW}  ▶ SOC ASSESSMENT:{C.RESET} {chain_label}")
        print()
        print(_col("  " + "─" * WIDTH, C.GREY))

    # Show standard SOC investigation flow
    print()
    _section("SOC INVESTIGATION FLOW")
    for phase in ATTACK_PHASES:
        print(f"  │  {C.CYAN}◈{C.RESET}  {phase}")
        if phase != ATTACK_PHASES[-1]:
            print(f"  │  {C.GREY}  ↓{C.RESET}")
    _divider()
    print()


# ---------------------------------------------------------------------------
# IOC Panel  (option 5)
# ---------------------------------------------------------------------------

def render_ioc_panel(iocs):
    """Renders all extracted Indicators of Compromise with category totals."""
    _header("INDICATORS OF COMPROMISE (IOC)")

    def _ioc_section(title, items, color):
        _section(f"{title}  [{len(items)}]")
        if items:
            for item in items:
                print(f"  │  {color}{item}{C.RESET}")
        else:
            print(f"  │  {C.GREY}None detected.{C.RESET}")
        _divider()

    total = (len(iocs.ip_addresses) + len(iocs.usernames) + len(iocs.processes) +
             len(iocs.hostnames) + len(iocs.domains) + len(iocs.hashes))

    print(f"\n  {C.BOLD}Total IOCs Extracted: {total}{C.RESET}")

    _ioc_section("IP ADDRESSES", iocs.ip_addresses, C.YELLOW)
    _ioc_section("USERS",        iocs.usernames,    C.CYAN)
    _ioc_section("PROCESSES",    iocs.processes,    C.WHITE)
    _ioc_section("HOSTNAMES",    iocs.hostnames,    C.GREY)
    _ioc_section("DOMAINS",      iocs.domains,      C.RED)
    _ioc_section("HASHES",       iocs.hashes,       C.ORANGE)

    if iocs.commands:
        _section(f"SUSPICIOUS COMMAND LINES  [{len(iocs.commands)}]")
        for cmd in iocs.commands[:5]:
            display = (cmd[:68] + "…") if len(cmd) > 68 else cmd
            print(f"  │  {C.GREY}{display}{C.RESET}")
        _divider()

    print()


# ---------------------------------------------------------------------------
# Evidence Panel  (option 6)
# ---------------------------------------------------------------------------

def render_evidence_panel(incidents):
    """Renders forensic evidence for every incident."""
    _header("EVIDENCE PANEL  ──  Forensic Investigation Notebook")

    if not incidents:
        print(f"\n  {C.GREY}No evidence to display. Run option 1 first.{C.RESET}\n")
        return

    for inc in incidents:
        if not inc.evidence:
            continue

        sev_color = SEVERITY_COLOR.get(inc.severity, C.WHITE)
        print()
        print(
            f"  {C.BOLD}{inc.incident_id}{C.RESET}  "
            f"{sev_color}[{inc.severity}]{C.RESET}  "
            f"{C.CYAN}{inc.technique_name}{C.RESET}"
        )

        for ev_idx, ev in enumerate(inc.evidence, start=1):
            print(f"  {C.GREY}┌── Evidence #{ev_idx}{C.RESET}")
            print(f"  {C.GREY}│  Timestamp     :{C.RESET} {ev.get('timestamp', '-')}")
            print(f"  {C.GREY}│  Event ID      :{C.RESET} {ev.get('event_id', '-')}")
            print(f"  {C.GREY}│  MITRE         :{C.RESET} {C.CYAN}{ev.get('mitre_technique', '-')}{C.RESET}")
            print(f"  {C.GREY}│  Matched Rule  :{C.RESET} {C.CYAN}{ev.get('matched_rule', '-')}{C.RESET}")
            print(f"  {C.GREY}│  IOC           :{C.RESET} {C.YELLOW}{ev.get('ioc', 'None')}{C.RESET}")

            reason = ev.get("reason", "-")
            reason_display = (reason[:65] + "…") if len(reason) > 65 else reason
            print(f"  {C.GREY}│  Reason        :{C.RESET} {reason_display}")

            raw = ev.get("raw_log", "-")
            raw_display = (raw[:70] + "…") if len(raw) > 70 else raw
            print(f"  {C.GREY}│  Raw Log       :{C.RESET} {C.GREY}{raw_display}{C.RESET}")
            print(f"  {C.GREY}└{'─'*62}{C.RESET}")

    print()


# ---------------------------------------------------------------------------
# MITRE Mapping View  (option 8)
# ---------------------------------------------------------------------------

def render_mitre_mapping(mitre_map):
    """Renders the full MITRE ATT&CK mapping table with detection logic."""
    from soc_engine import TECHNIQUE_TACTICS, TECHNIQUE_DESCRIPTIONS

    _header("MITRE ATT&CK MAPPING  ──  Technique Reference")

    for event_id, entry in sorted(mitre_map.items(), key=lambda x: x[0]):
        if event_id == "unknown":
            continue

        category = entry.get("category", "Uncategorized")
        default  = entry.get("default", {})
        tech_id  = default.get("technique_id", "N/A")
        tactic   = TECHNIQUE_TACTICS.get(tech_id, "-")
        severity = default.get("severity", "Low")
        sev_color = SEVERITY_COLOR.get(severity, C.WHITE)

        print()
        print(
            f"  {C.BOLD}Event ID {event_id}{C.RESET}  {C.GREY}–{C.RESET}  "
            f"{C.CYAN}{category}{C.RESET}"
        )
        print(
            f"  {C.GREY}Tactic   :{C.RESET} {tactic}"
            f"   {C.GREY}Technique:{C.RESET} {tech_id} – {default.get('technique_name', 'Unknown')}"
            f"   {C.GREY}Severity :{C.RESET} {sev_color}{severity}{C.RESET}"
        )

        desc = TECHNIQUE_DESCRIPTIONS.get(tech_id, default.get("description", ""))
        if desc:
            print(f"  {C.GREY}Detect   : {desc[:70]}{C.RESET}")

        for rule in entry.get("process_rules", []):
            rule_sev = rule.get("severity", "Low")
            rule_color = SEVERITY_COLOR.get(rule_sev, C.WHITE)
            print(
                f"  {C.GREY}  ↳ rule [{rule.get('keyword')}]{C.RESET}  "
                f"{C.CYAN}{rule.get('technique_id')} – {rule.get('technique_name')}{C.RESET}  "
                f"[{rule_color}{rule_sev}{C.RESET}]"
            )

    print()


# ---------------------------------------------------------------------------
# Search Event ID  (option 7)
# ---------------------------------------------------------------------------

# SOC investigation guidance per Event ID
SOC_GUIDANCE = {
    "1":    "Check parent process, user context, and full command line. Encoded PowerShell is an immediate escalation trigger.",
    "3":    "Verify destination IP reputation via threat intel. Outbound connections from cmd.exe or PowerShell are high priority.",
    "4624": "Correlate with prior 4625 failures. Check logon type (2=interactive, 3=network, 10=remote). Unexpected logons need investigation.",
    "4625": "Track frequency and source IP. 3+ failures in 60 seconds trigger brute force rule. Check if account is admin-level.",
    "7":    "Check DLL signature, path, and hash. Suspicious paths: Temp, AppData, Downloads. Submit hash to VirusTotal.",
}

DEFAULT_GUIDANCE = "Review event context, correlate with related incidents, and assess risk based on user, host, and network indicators."


def render_search_result(event_id, matches, mitre_map):
    """Renders search results for a specific Event ID with SOC guidance."""
    from soc_engine import TECHNIQUE_TACTICS

    _header(f"EVENT ID SEARCH  ──  Event ID {event_id}")

    if not matches:
        print(f"\n  {C.GREY}No incidents found for Event ID {event_id}.{C.RESET}")
        print(f"  {C.GREY}This Event ID either did not appear in the logs or is not mapped.{C.RESET}\n")
        return

    first     = matches[0]
    tactic    = TECHNIQUE_TACTICS.get(first.technique_id, "-")
    sev_color = SEVERITY_COLOR.get(first.severity, C.WHITE)

    # Technique summary
    _section("TECHNIQUE DETAILS")
    _row("Event ID",       event_id,             C.WHITE)
    _row("Category",       first.category,       C.CYAN)
    _row("Technique ID",   first.technique_id,   C.CYAN)
    _row("Technique Name", first.technique_name, C.WHITE)
    _row("Tactic",         tactic,               C.BLUE)
    _row("Severity",       first.severity,       sev_color)
    _row("Occurrences",    len(matches),         C.YELLOW)
    _divider()

    # Description
    _section("EVENT DESCRIPTION")
    for line in _wrap_text(first.description):
        print(_col(line, C.GREY))
    _divider()

    # SOC investigation guidance
    _section("SOC INVESTIGATION GUIDANCE")
    guidance = SOC_GUIDANCE.get(event_id, DEFAULT_GUIDANCE)
    for line in _wrap_text(guidance):
        print(_col(line, C.YELLOW))
    _divider()

    # Recommendation
    _section("RECOMMENDED ACTIONS")
    for line in _wrap_text(first.recommendation):
        print(_col(line, C.WHITE))
    _divider()

    # Related incidents
    _section("RELATED INCIDENTS")
    for m in matches:
        msev_color = SEVERITY_COLOR.get(m.severity, C.WHITE)
        disp, dcol = _classify_disposition(m)
        print(
            f"  │  {C.GREY}{m.timestamp}{C.RESET}  "
            f"{msev_color}[{m.severity:<8}]{C.RESET}  "
            f"{C.BOLD}{dcol}[{disp}]{C.RESET}  "
            f"{C.GREY}{m.incident_id}{C.RESET}  "
            f"{m.category}"
        )
    _divider()
    print()
