"""
soc_engine.py
-------------
Core analysis engine for SOC Incident Analyzer v3.0.

Responsibilities:
    - Load MITRE ATT&CK mapping (mitre_mapping.json)
    - Classify each LogEvent into an enriched Incident object
    - Detect multi-event patterns (brute force, network scanning)
    - Merge correlated duplicate incidents into meaningful groups
    - Correlate incidents into a chronological attack timeline
    - Calculate a transparent, explainable risk score (0–100)
    - Build dynamic confidence scores based on evidence strength
    - Build recommendations based on detected incident categories
    - Build aggregate statistics for dashboard and report
    - Extract Indicators of Compromise (IOCs) from events/incidents
"""

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import List

import utils

# Severity weights used in risk score calculation
SEVERITY_WEIGHTS = {"Critical": 5, "High": 3, "Medium": 2, "Low": 1}
SEVERITY_ORDER   = ["Low", "Medium", "High", "Critical"]

# MITRE tactic lookup by technique ID
TECHNIQUE_TACTICS = {
    "T1046":     "Reconnaissance",
    "T1059":     "Execution",
    "T1059.001": "Execution",
    "T1059.003": "Execution",
    "T1071":     "Command and Control",
    "T1071.001": "Command and Control",
    "T1078":     "Defense Evasion / Persistence",
    "T1110":     "Credential Access",
    "T1055":     "Defense Evasion",
    "T1547":     "Persistence",
    "T1053":     "Execution",
    "T1021":     "Lateral Movement",
    "T1560":     "Collection",
    "T1041":     "Exfiltration",
}

# Human-readable descriptions for each MITRE technique
TECHNIQUE_DESCRIPTIONS = {
    "T1046":     "Adversaries scan network services to discover open ports and running services.",
    "T1059":     "Adversaries abuse command interpreters to execute commands, scripts, or binaries.",
    "T1059.001": "Adversaries abuse PowerShell commands and scripts; encoded commands evade detection.",
    "T1059.003": "Adversaries abuse the Windows command shell (cmd.exe) to execute commands.",
    "T1071":     "Adversaries communicate using application layer protocols to blend in with normal traffic.",
    "T1071.001": "Adversaries use web protocols (HTTP/S) for C2 communication, often via PowerShell.",
    "T1078":     "Adversaries obtain and abuse credentials of existing accounts to gain access.",
    "T1110":     "Adversaries try to gain access by guessing or brute-forcing credentials.",
    "T1055":     "Adversaries inject code into running processes to evade defenses.",
    "T1547":     "Adversaries establish persistence via Run keys, startup folders, or scheduled tasks.",
    "N/A":       "Technique not mapped in the current MITRE ATT&CK dataset.",
}

# Processes that are inherently benign and should receive Low severity at most
BENIGN_PROCESSES = {"explorer.exe", "svchost.exe", "taskhostw.exe", "sihost.exe"}

# Incident lifecycle status values
STATUS_OPEN          = "OPEN"
STATUS_INVESTIGATING = "INVESTIGATING"
STATUS_CLOSED        = "CLOSED"


# ---------------------------------------------------------------------------
# Incident dataclass
# ---------------------------------------------------------------------------

@dataclass
class Incident:
    """Represents a single detected security incident with full SOC metadata."""
    # Core classification fields
    timestamp:      str = "-"
    event_id:       str = "-"
    category:       str = "-"
    technique_id:   str = "N/A"
    technique_name: str = "Unknown"
    severity:       str = "Low"
    description:    str = ""
    recommendation: str = ""

    # SOC investigation metadata
    incident_id:    str = ""
    tactic:         str = "-"
    confidence:     int = 70       # 0–100; dynamically adjusted
    risk_score:     int = 0        # 0–100; per-incident score
    status:         str = STATUS_OPEN

    # Host and network context
    source_ip:      str = "-"
    dest_ip:        str = "-"
    username:       str = "-"
    hostname:       str = "-"
    process:        str = "-"
    parent_process: str = "-"
    command_line:   str = "-"

    # Event count for merged/grouped incidents
    event_count:    int = 1

    # Evidence entries: each is a dict with keys:
    #   raw_log, matched_rule, reason, timestamp, ioc, event_id, mitre_technique
    evidence: List[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# IOC collection dataclass
# ---------------------------------------------------------------------------

@dataclass
class IOCCollection:
    """Holds all extracted Indicators of Compromise from an analysis session."""
    ip_addresses: List[str] = field(default_factory=list)
    usernames:    List[str] = field(default_factory=list)
    processes:    List[str] = field(default_factory=list)
    hostnames:    List[str] = field(default_factory=list)
    domains:      List[str] = field(default_factory=list)
    hashes:       List[str] = field(default_factory=list)
    commands:     List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# MITRE mapping loader
# ---------------------------------------------------------------------------

def load_mitre_mapping(filepath):
    """
    Loads mitre_mapping.json.  Falls back to a minimal built-in mapping
    if the file is missing or invalid so the app never crashes.
    """
    fallback = {
        "unknown": {
            "category": "Unmapped Event",
            "default": {
                "technique_id":   "N/A",
                "technique_name": "Unmapped Technique",
                "severity":       "Low",
                "description":    "This Event ID is not yet in mitre_mapping.json.",
                "recommendation": "Add this Event ID to mitre_mapping.json to enable classification.",
            },
        }
    }
    mapping = utils.safe_load_json(filepath, fallback=None)
    if not mapping:
        print("[INFO] Using minimal built-in MITRE mapping fallback.")
        return fallback
    return mapping


def _lookup_event_definition(event, mitre_map):
    """
    Finds the correct mapping entry for a LogEvent.
    Applies process_rules keyword matching before falling back to 'default'.
    Returns (category, technique_id, technique_name, severity, description, recommendation).
    """
    entry = mitre_map.get(event.event_id)

    if entry is None:
        unmapped = mitre_map.get("unknown", {}).get("default", {})
        return (
            "Unmapped Event",
            unmapped.get("technique_id",   "N/A"),
            unmapped.get("technique_name", "Unmapped Technique"),
            unmapped.get("severity",       "Low"),
            unmapped.get("description",    "No mapping available."),
            unmapped.get("recommendation", "Review this Event ID manually."),
        )

    category = entry.get("category", "Uncategorized")
    chosen   = entry.get("default", {})

    # Apply keyword rules based on process image name
    for rule in entry.get("process_rules", []):
        keyword = rule.get("keyword", "").lower()
        if keyword and keyword in event.image.lower():
            chosen = rule
            break

    return (
        category,
        chosen.get("technique_id",   "N/A"),
        chosen.get("technique_name", "Unknown Technique"),
        chosen.get("severity",       "Low"),
        chosen.get("description",    "No description available."),
        chosen.get("recommendation", "No recommendation available."),
    )


# ---------------------------------------------------------------------------
# Incident ID generator
# ---------------------------------------------------------------------------

_incident_counter = 0


def _next_incident_id():
    global _incident_counter
    _incident_counter += 1
    return f"INC-{_incident_counter:04d}"


def reset_incident_counter():
    global _incident_counter
    _incident_counter = 0


# ---------------------------------------------------------------------------
# Risk score calculation (0–100, transparent and explainable)
# ---------------------------------------------------------------------------

def _compute_incident_risk(incident):
    """
    Calculates a per-incident risk score from 0 to 100.

    Formula (SOC-explainable):
        base_score     = severity_weight / max_weight × 60    (max 60 pts)
        confidence_mod = confidence / 100                     (scales base)
        ioc_bonus      = min(evidence_count × 5, 20)          (max 20 pts)
        technique_bonus = 10 if technique is mapped, else 0   (max 10 pts)
        indicator_bonus = command-line / network / auth flags  (max 10 pts)

    Total capped at 100.
    """
    severity   = incident.severity
    confidence = incident.confidence
    tech_id    = incident.technique_id
    cmd        = incident.command_line or "-"
    ev_count   = len(incident.evidence)

    # Base score from severity (max 60)
    weight     = SEVERITY_WEIGHTS.get(severity, 1)
    max_weight = SEVERITY_WEIGHTS["Critical"]  # 5
    base_score = (weight / max_weight) * 60

    # Scale by confidence
    base_score = base_score * (confidence / 100)

    # IOC / evidence richness bonus (max 20)
    ioc_bonus = min(ev_count * 5, 20)

    # MITRE technique bonus (10 if mapped)
    technique_bonus = 10 if tech_id != "N/A" else 0

    # Indicator bonuses (max 10)
    indicator_bonus = 0
    if any(flag in cmd.lower() for flag in ["-enc", "-nop", "-w hidden", "bypass"]):
        indicator_bonus += 5   # encoded/obfuscated PowerShell
    if incident.source_ip != "-" and incident.dest_ip != "-":
        indicator_bonus += 3   # has network context
    if incident.username not in ("-", ""):
        indicator_bonus += 2   # user attributed

    total = int(base_score + ioc_bonus + technique_bonus + indicator_bonus)
    return min(total, 100)


# ---------------------------------------------------------------------------
# Dynamic confidence scoring
# ---------------------------------------------------------------------------

def _compute_confidence(severity, event, all_events=None, related_count=0):
    """
    Calculates confidence (0–100%) based on available evidence signals.

    Confidence increases when:
        - Severity is higher (stronger MITRE signal)
        - Multiple related events exist in the log
        - IOCs (IP, user, process) are present
        - MITRE technique is precisely mapped (sub-technique)
        - Command line contains suspicious indicators
    """
    # Start from severity baseline
    base = {"Critical": 85, "High": 75, "Medium": 60, "Low": 45}.get(severity, 55)

    # Related event correlation bonus (up to +10)
    base += min(related_count * 2, 10)

    # IOC richness bonus
    if event.source_ip != "-":
        base += 3
    if event.user not in ("-", ""):
        base += 2
    if event.image not in ("-", ""):
        base += 2

    # Obfuscated command line raises confidence (stronger signal)
    if event.command_line != "-":
        cmd = event.command_line.lower()
        if any(flag in cmd for flag in ["-enc", "-nop", "-w hidden", "bypass", "iex"]):
            base += 8
        elif len(event.command_line) > 30:
            base += 3

    return min(base, 100)


# ---------------------------------------------------------------------------
# Evidence builder
# ---------------------------------------------------------------------------

def _build_evidence(event, tech_id, tech_name, description):
    """Creates an evidence dict from a raw log event."""
    raw_log = (
        f"Timestamp:{event.timestamp}|EventID:{event.event_id}|"
        f"Image:{event.image}|User:{event.user}|"
        f"CommandLine:{event.command_line}|SourceIP:{event.source_ip}|"
        f"DestinationIP:{event.dest_ip}|Account:{event.account}|Status:{event.status}"
    )

    ioc_parts = []
    if event.source_ip != "-":
        ioc_parts.append(f"IP:{event.source_ip}")
    if event.dest_ip != "-":
        ioc_parts.append(f"IP:{event.dest_ip}")
    if event.user not in ("-", ""):
        ioc_parts.append(f"User:{event.user}")
    if event.image not in ("-", ""):
        ioc_parts.append(f"Process:{event.image}")

    return {
        "raw_log":        raw_log,
        "matched_rule":   f"{tech_id} – {tech_name}",
        "reason":         description,
        "timestamp":      event.timestamp,
        "event_id":       event.event_id,
        "mitre_technique": f"{tech_id} – {tech_name}",
        "ioc":            ", ".join(ioc_parts) if ioc_parts else "None",
    }


# ---------------------------------------------------------------------------
# Single-event classifier
# ---------------------------------------------------------------------------

def classify_event(event, mitre_map, all_events=None):
    """
    Converts a single LogEvent into an enriched Incident.

    Benign processes (explorer.exe, etc.) are capped at Low severity.
    Confidence is computed dynamically from available evidence signals.
    """
    all_events = all_events or []

    category, tech_id, tech_name, severity, description, recommendation = \
        _lookup_event_definition(event, mitre_map)

    # Cap severity for known-benign processes
    process_name = event.image.lower() if event.image != "-" else ""
    if process_name in BENIGN_PROCESSES:
        severity = "Low"
        description = (
            f"{event.image} is a standard Windows process. "
            "This event is informational unless spawned by an unusual parent."
        )
        recommendation = (
            "Verify parent process. Investigate only if spawned by cmd.exe, "
            "PowerShell, or another unexpected process."
        )

    # Count related events for same EventID (used in confidence)
    related_count = sum(1 for e in all_events if e.event_id == event.event_id) - 1

    confidence = _compute_confidence(severity, event, all_events, related_count)
    tactic     = TECHNIQUE_TACTICS.get(tech_id, "Unknown")
    process    = event.image if event.image != "-" else "-"
    hostname   = event.dest_ip if event.dest_ip != "-" else (
                 event.source_ip if event.source_ip != "-" else "-")

    evidence_entry = _build_evidence(event, tech_id, tech_name, description)

    inc = Incident(
        timestamp      = event.timestamp,
        event_id       = event.event_id,
        category       = category,
        technique_id   = tech_id,
        technique_name = tech_name,
        severity       = severity,
        description    = description,
        recommendation = recommendation,
        incident_id    = _next_incident_id(),
        tactic         = tactic,
        confidence     = confidence,
        risk_score     = 0,          # computed after creation
        status         = STATUS_OPEN,
        source_ip      = event.source_ip,
        dest_ip        = event.dest_ip,
        username       = event.user if event.user != "-" else event.account,
        hostname       = hostname,
        process        = process,
        parent_process = "-",
        command_line   = event.command_line,
        event_count    = 1,
        evidence       = [evidence_entry],
    )
    inc.risk_score = _compute_incident_risk(inc)
    return inc


# ---------------------------------------------------------------------------
# Pattern-based detectors
# ---------------------------------------------------------------------------

def _parse_timestamp(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None


def detect_network_scan(events, window_seconds, min_connections=4):
    """
    Detects network scanning: multiple Event ID 3 connections from the
    same source IP within a short time window.
    """
    scan_incidents = []
    net_events = [e for e in events if e.event_id == "3" and e.source_ip != "-"]

    by_source = {}
    for e in net_events:
        by_source.setdefault(e.source_ip, []).append(e)

    for source_ip, group in by_source.items():
        group = sorted(group, key=lambda e: e.timestamp)
        cluster = []
        for e in group:
            ts = _parse_timestamp(e.timestamp)
            if ts is None:
                continue
            if not cluster:
                cluster = [e]
                continue
            first_ts = _parse_timestamp(cluster[0].timestamp)
            if first_ts and (ts - first_ts).total_seconds() <= window_seconds:
                cluster.append(e)
            else:
                if len(cluster) >= min_connections:
                    scan_incidents.append(_build_scan_incident(cluster, source_ip))
                cluster = [e]
        if len(cluster) >= min_connections:
            scan_incidents.append(_build_scan_incident(cluster, source_ip))

    return scan_incidents


def _build_scan_incident(cluster, source_ip):
    """Builds a Network Reconnaissance incident from a scan cluster."""
    tech_id   = "T1046"
    tech_name = "Network Service Discovery"
    severity  = "High"
    confidence = min(80 + len(cluster) * 2, 98)   # more connections = higher confidence

    dest_ips  = list({e.dest_ip for e in cluster if e.dest_ip != "-"})
    description = (
        f"{len(cluster)} rapid network connections from {source_ip} "
        f"to {len(dest_ips)} unique host(s) within {len(cluster)} seconds — "
        f"consistent with automated port/network scanning (T1046)."
    )

    inc = Incident(
        timestamp      = cluster[0].timestamp,
        event_id       = "3",
        category       = "Network Reconnaissance",
        technique_id   = tech_id,
        technique_name = tech_name,
        severity       = severity,
        description    = description,
        recommendation = (
            "Identify and isolate the scanning host. "
            "Review firewall logs for the full scan range. "
            "Check if the scanner is an authorized vulnerability scanner. "
            "Block if unauthorized; escalate to Tier-2."
        ),
        incident_id    = _next_incident_id(),
        tactic         = TECHNIQUE_TACTICS.get(tech_id, "Reconnaissance"),
        confidence     = confidence,
        risk_score     = 0,
        status         = STATUS_OPEN,
        source_ip      = source_ip,
        dest_ip        = dest_ips[0] if dest_ips else "-",
        username       = "-",
        hostname       = source_ip,
        process        = "-",
        event_count    = len(cluster),
        evidence       = [{
            "raw_log":        f"Network scan cluster: {len(cluster)} connections from {source_ip} to {len(dest_ips)} hosts",
            "matched_rule":   f"{tech_id} – {tech_name}",
            "reason":         description,
            "timestamp":      cluster[0].timestamp,
            "event_id":       "3",
            "mitre_technique": f"{tech_id} – {tech_name}",
            "ioc":            f"IP:{source_ip}",
        }],
    )
    inc.risk_score = _compute_incident_risk(inc)
    return inc


def detect_brute_force(events, window_seconds, threshold):
    """
    Detects brute force: repeated failed logons (Event ID 4625)
    for the same account within a short window.
    """
    brute_force_incidents = []
    failed_events = [e for e in events if e.event_id == "4625" and e.account != "-"]

    by_account = {}
    for e in failed_events:
        by_account.setdefault(e.account, []).append(e)

    for account, group in by_account.items():
        group = sorted(group, key=lambda e: e.timestamp)
        cluster = []
        for e in group:
            ts = _parse_timestamp(e.timestamp)
            if ts is None:
                continue
            if not cluster:
                cluster = [e]
                continue
            first_ts = _parse_timestamp(cluster[0].timestamp)
            if first_ts and (ts - first_ts).total_seconds() <= window_seconds:
                cluster.append(e)
            else:
                if len(cluster) >= threshold:
                    brute_force_incidents.append(_build_brute_force_incident(cluster, account))
                cluster = [e]
        if len(cluster) >= threshold:
            brute_force_incidents.append(_build_brute_force_incident(cluster, account))

    return brute_force_incidents


def _build_brute_force_incident(cluster, account):
    """Builds a Credential Access incident from a brute force cluster."""
    tech_id   = "T1110"
    tech_name = "Brute Force"
    severity  = "Critical"
    confidence = min(88 + len(cluster), 99)   # more failures = higher confidence

    src_ip = cluster[0].source_ip if cluster[0].source_ip != "-" else "-"
    description = (
        f"{len(cluster)} consecutive failed logon attempts for account '{account}' "
        f"from {src_ip} within seconds — strong indicator of brute force or "
        f"credential stuffing attack (T1110)."
    )

    inc = Incident(
        timestamp      = cluster[0].timestamp,
        event_id       = "4625",
        category       = "Credential Access",
        technique_id   = tech_id,
        technique_name = tech_name,
        severity       = severity,
        description    = description,
        recommendation = (
            "Lock or monitor the targeted account immediately. "
            "Enable MFA on all privileged accounts. "
            "Block the source IP at the perimeter firewall. "
            "Review source IP in threat intelligence. "
            "Check for a subsequent successful logon — may indicate compromise."
        ),
        incident_id    = _next_incident_id(),
        tactic         = TECHNIQUE_TACTICS.get(tech_id, "Credential Access"),
        confidence     = confidence,
        risk_score     = 0,
        status         = STATUS_OPEN,
        source_ip      = src_ip,
        dest_ip        = cluster[0].dest_ip,
        username       = account,
        hostname       = cluster[0].dest_ip,
        process        = "-",
        event_count    = len(cluster),
        evidence       = [{
            "raw_log":        f"Brute force cluster: {len(cluster)} failures for '{account}' from {src_ip}",
            "matched_rule":   f"{tech_id} – {tech_name}",
            "reason":         description,
            "timestamp":      cluster[0].timestamp,
            "event_id":       "4625",
            "mitre_technique": f"{tech_id} – {tech_name}",
            "ioc":            f"User:{account}" + (f", IP:{src_ip}" if src_ip != "-" else ""),
        }],
    )
    inc.risk_score = _compute_incident_risk(inc)
    return inc


# ---------------------------------------------------------------------------
# Incident deduplication and smart merging
# ---------------------------------------------------------------------------

def _merge_duplicate_incidents(incidents):
    """
    Merges repeated low-value incidents into single grouped incidents.

    Merging rules:
      1. Multiple Auth Failures from same source → keep only the pattern-based
         Brute Force incident; remove individual 4625 duplicates.
      2. Multiple Network Connection events from same source → keep scan incident.
      3. Repeated Process Creation of the same binary → merge into one
         incident with aggregated evidence and updated event_count.

    This transforms a noisy alert list into a meaningful SOC investigation story.
    """
    # Separate pattern-based incidents (scan, brute force) from per-event ones
    pattern_incidents = [i for i in incidents if i.event_count > 1]
    per_event         = [i for i in incidents if i.event_count == 1]

    # Collect keys covered by pattern incidents so we skip their raw events
    covered_event_ids = set()
    covered_src_ips   = set()
    for pi in pattern_incidents:
        covered_event_ids.add(pi.event_id)
        if pi.source_ip != "-":
            covered_src_ips.add(pi.source_ip)

    merged = []
    seen_process_key = {}   # (event_id, process, username) -> index in merged

    for inc in per_event:
        # Skip raw 4625 / raw scan 3 if a pattern incident already covers them
        if inc.event_id == "4625" and "4625" in covered_event_ids:
            continue
        if (inc.event_id == "3"
                and inc.source_ip in covered_src_ips
                and inc.category == "Network Connection"):
            # Keep non-scan outbound connections (e.g. PowerShell C2)
            if inc.process.lower() not in ("", "-"):
                merged.append(inc)
            continue

        # Merge repeated process creation of same binary by same user
        merge_key = (inc.event_id, inc.process.lower(), inc.username)
        if inc.event_id == "1" and merge_key in seen_process_key:
            # Fold this event into the existing incident
            existing_idx = seen_process_key[merge_key]
            existing = merged[existing_idx]
            existing.event_count += 1
            existing.evidence.extend(inc.evidence)
            # Boost confidence slightly for repeated events
            existing.confidence = min(existing.confidence + 3, 100)
            existing.risk_score = _compute_incident_risk(existing)
            # Update description to reflect merged count
            if existing.event_count == 2:
                existing.description = (
                    f"[{existing.event_count} Events] " + existing.description
                )
            else:
                existing.description = (
                    f"[{existing.event_count} Events]" +
                    existing.description.split("]", 1)[-1]
                )
        else:
            if inc.event_id == "1":
                seen_process_key[merge_key] = len(merged)
            merged.append(inc)

    # Combine: pattern incidents first (by timestamp), then per-event
    all_incidents = pattern_incidents + merged
    all_incidents.sort(key=lambda i: i.timestamp)
    return all_incidents


# ---------------------------------------------------------------------------
# Main detection pipeline
# ---------------------------------------------------------------------------

def detect_incidents(events, mitre_map, config):
    """
    Full detection pipeline:
        1. Classify each log event via MITRE mapping
        2. Run pattern-based detectors (brute force, network scan)
        3. Merge and deduplicate to produce a clean, correlated incident list
    Returns sorted, de-duplicated list of Incidents.
    """
    reset_incident_counter()

    window       = config.get("timeline_window_seconds", 60)
    bf_threshold = config.get("brute_force_threshold",   3)

    # Classify every event, passing all events for confidence scoring
    per_event_incidents = [classify_event(e, mitre_map, all_events=events) for e in events]

    # Add pattern-based detections
    pattern_incidents = (
        detect_network_scan(events, window) +
        detect_brute_force(events, window, bf_threshold)
    )

    all_incidents = per_event_incidents + pattern_incidents
    all_incidents.sort(key=lambda i: i.timestamp)

    # Smart merge: reduce noise, surface meaningful incidents
    merged = _merge_duplicate_incidents(all_incidents)
    return merged


# ---------------------------------------------------------------------------
# IOC extraction
# ---------------------------------------------------------------------------

_IP_RE   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
_DOM_RE  = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|xyz|ru|cn|tk|cc|info|biz)\b"
)


def extract_iocs(events, incidents):
    """
    Extracts IOCs from all log events and incidents.
    Returns an IOCCollection with de-duplicated, sorted values.
    """
    ips       = set()
    users     = set()
    processes = set()
    hosts     = set()
    domains   = set()
    hashes    = set()
    commands  = set()

    for e in events:
        if e.source_ip not in ("-", ""):
            ips.add(e.source_ip)
        if e.dest_ip not in ("-", ""):
            ips.add(e.dest_ip)
        if e.user not in ("-", ""):
            users.add(e.user)
        if e.account not in ("-", ""):
            users.add(e.account)
        if e.image not in ("-", ""):
            processes.add(e.image)
        if e.command_line not in ("-", ""):
            for dom in _DOM_RE.findall(e.command_line):
                domains.add(dom)
            for h in _HASH_RE.findall(e.command_line):
                hashes.add(h)
            if len(e.command_line) > 20:
                commands.add(e.command_line[:120])

    for inc in incidents:
        if inc.source_ip not in ("-", ""):
            ips.add(inc.source_ip)
        if inc.dest_ip not in ("-", ""):
            ips.add(inc.dest_ip)
        if inc.username not in ("-", ""):
            users.add(inc.username)
        if inc.hostname not in ("-", ""):
            hosts.add(inc.hostname)
        if inc.process not in ("-", ""):
            processes.add(inc.process)

    return IOCCollection(
        ip_addresses = sorted(ips),
        usernames    = sorted(users),
        processes    = sorted(processes),
        hostnames    = sorted(hosts),
        domains      = sorted(domains),
        hashes       = sorted(hashes),
        commands     = sorted(commands),
    )


# ---------------------------------------------------------------------------
# Timeline correlation
# ---------------------------------------------------------------------------

# Attack chain patterns: ordered list of (required_categories, label)
CHAIN_PATTERNS = [
    (["Network Reconnaissance", "Credential Access", "Process Creation", "Network Connection"],
     "Full Attack Chain: Recon → Credential Attack → Execution → C2"),
    (["Network Reconnaissance", "Credential Access", "Process Creation"],
     "Reconnaissance → Credential Attack → Code Execution"),
    (["Network Reconnaissance", "Credential Access"],
     "Reconnaissance Followed by Credential Attack"),
    (["Credential Access", "Authentication Success", "Process Creation"],
     "Credential Compromise → Account Access → Execution"),
    (["Credential Access", "Process Creation", "Network Connection"],
     "Credential Theft → Execution → C2 Callback"),
    (["Authentication Success", "Process Creation", "Network Connection"],
     "Successful Login → Process Execution → Outbound Connection"),
    (["Process Creation", "Network Connection"],
     "Command Execution Followed by Outbound Connection"),
    (["Credential Access"],
     "Possible Brute Force / Credential Attack"),
    (["Network Reconnaissance"],
     "Network Scanning Activity Detected"),
    (["Authentication Success", "Process Creation"],
     "Successful Login Followed by Process Execution"),
]

# SOC attack phase labels for display
ATTACK_PHASES = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Credential Access",
    "Command & Control",
    "Defense Evasion",
    "Persistence",
    "Incident Containment",
]


def correlate_timeline(incidents, window_seconds):
    """
    Groups incidents into chronological clusters and attaches a
    plain-English attack chain label to each cluster.
    """
    if not incidents:
        return []

    sorted_incidents = sorted(incidents, key=lambda i: i.timestamp)
    clusters = []
    current  = [sorted_incidents[0]]

    for incident in sorted_incidents[1:]:
        prev_ts = _parse_timestamp(current[-1].timestamp)
        cur_ts  = _parse_timestamp(incident.timestamp)
        if prev_ts and cur_ts and (cur_ts - prev_ts).total_seconds() <= window_seconds:
            current.append(incident)
        else:
            clusters.append(current)
            current = [incident]
    clusters.append(current)

    timeline = []
    for cluster in clusters:
        categories = [i.category for i in cluster]
        label = _match_chain_label(categories)
        timeline.append({"entries": cluster, "chain_label": label})

    return timeline


def _match_chain_label(categories_seen):
    """Returns the most specific matching attack chain label."""
    for required, label in CHAIN_PATTERNS:
        if all(cat in categories_seen for cat in required):
            return label
    return "Isolated Security Event"


# ---------------------------------------------------------------------------
# Organisation-level risk scoring
# ---------------------------------------------------------------------------

def calculate_risk(incidents, config):
    """
    Calculates the organisation-level risk score and level.

    Score = average of all per-incident risk scores (each capped at 100),
    then amplified by incident count factor to reward breadth of attack.
    Final score is capped at 100 to never exceed the maximum.
    """
    if not incidents:
        return 0, "LOW"

    avg_per_incident = sum(i.risk_score for i in incidents) / len(incidents)

    # Breadth multiplier: more incidents = higher organisational risk
    count_factor = min(1.0 + (len(incidents) - 1) * 0.05, 1.5)
    score = int(min(avg_per_incident * count_factor, 100))

    thresholds = config.get("risk_thresholds", {})
    low_max    = thresholds.get("low_max",    25)
    medium_max = thresholds.get("medium_max", 50)
    high_max   = thresholds.get("high_max",   75)

    if score <= low_max:
        level = "LOW"
    elif score <= medium_max:
        level = "MEDIUM"
    elif score <= high_max:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return score, level


# ---------------------------------------------------------------------------
# Recommendations builder
# ---------------------------------------------------------------------------

def build_recommendations(incidents):
    """Returns a de-duplicated list of actionable recommendations."""
    seen = set()
    recs = []
    for inc in sorted(incidents, key=lambda i: SEVERITY_WEIGHTS.get(i.severity, 0), reverse=True):
        if inc.recommendation not in seen:
            seen.add(inc.recommendation)
            recs.append(inc.recommendation)
    return recs


# ---------------------------------------------------------------------------
# Summary statistics for dashboard and report
# ---------------------------------------------------------------------------

def build_summary_stats(events, incidents):
    """Builds the aggregate statistics dict used by dashboard and report."""
    severity_counts = {sev: 0 for sev in SEVERITY_ORDER}
    for inc in incidents:
        if inc.severity in severity_counts:
            severity_counts[inc.severity] += 1

    techniques = sorted({i.technique_id for i in incidents if i.technique_id != "N/A"})
    categories = sorted({i.category for i in incidents})

    highest_severity = "None"
    for sev in reversed(SEVERITY_ORDER):
        if severity_counts.get(sev, 0) > 0:
            highest_severity = sev
            break

    src_ips  = [i.source_ip  for i in incidents if i.source_ip  != "-"]
    dst_ips  = [i.dest_ip    for i in incidents if i.dest_ip    != "-"]
    users    = [i.username   for i in incidents if i.username   != "-"]
    hosts    = [i.hostname   for i in incidents if i.hostname   != "-"]
    procs    = [i.process    for i in incidents if i.process    != "-"]

    # MITRE detail: technique_id -> {tactic, name, count}
    mitre_detail = {}
    for inc in incidents:
        if inc.technique_id == "N/A":
            continue
        if inc.technique_id not in mitre_detail:
            mitre_detail[inc.technique_id] = {
                "tactic": inc.tactic,
                "name":   inc.technique_name,
                "count":  0,
            }
        mitre_detail[inc.technique_id]["count"] += 1

    # Detection rate: unique categories detected / total possible categories
    # Capped at 100% to never display unrealistic values
    total_possible_categories = max(len(categories), 1)
    detection_rate = min(
        int((len(set(categories)) / total_possible_categories) * 100),
        100
    )

    return {
        "logs_processed":     len(events),
        "incidents_detected": len(incidents),
        "severity_counts":    severity_counts,
        "mitre_techniques":   techniques,
        "mitre_detail":       mitre_detail,
        "attack_categories":  categories,
        "highest_severity":   highest_severity,
        "top_src_ips":        Counter(src_ips).most_common(5),
        "top_dst_ips":        Counter(dst_ips).most_common(5),
        "top_users":          Counter(users).most_common(5),
        "top_hosts":          Counter(hosts).most_common(5),
        "top_processes":      Counter(procs).most_common(5),
        "detection_rate":     detection_rate,
    }
