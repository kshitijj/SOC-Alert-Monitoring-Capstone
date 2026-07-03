"""
parser.py
---------
Reads the raw log file and converts each valid line into a structured
LogEvent object.

Expected log line format (pipe-separated Key:Value pairs):

    Timestamp:2026-06-22 10:15:14|EventID:1|Image:powershell.exe|User:Administrator|
    CommandLine:...|SourceIP:...|DestinationIP:...|Account:...|Status:...

Lines that don't follow this format are skipped (with a warning),
never crashing the application.
"""

from dataclasses import dataclass
import utils

# Fields we expect to find in each log line, and the LogEvent attribute
# they map to. Any field not present in a given line simply defaults to "-".
EXPECTED_FIELDS = {
    "Timestamp": "timestamp",
    "EventID": "event_id",
    "Image": "image",
    "User": "user",
    "CommandLine": "command_line",
    "SourceIP": "source_ip",
    "DestinationIP": "dest_ip",
    "Account": "account",
    "Status": "status",
}


@dataclass
class LogEvent:
    """Represents a single structured security log entry."""
    timestamp: str = "-"
    event_id: str = "-"
    image: str = "-"
    user: str = "-"
    command_line: str = "-"
    source_ip: str = "-"
    dest_ip: str = "-"
    account: str = "-"
    status: str = "-"


def _parse_line(line):
    """
    Parses a single pipe-separated log line into a LogEvent.
    Returns None if the line cannot be parsed (malformed line).
    """
    fields = {}

    for chunk in line.split("|"):
        chunk = chunk.strip()
        if ":" not in chunk:
            # Not a valid Key:Value pair -> treat whole line as malformed
            return None

        key, value = chunk.split(":", 1)
        key = key.strip()
        value = value.strip()

        if key in EXPECTED_FIELDS:
            fields[EXPECTED_FIELDS[key]] = value if value else "-"

    # A valid log line must at minimum contain an EventID to be useful
    if "event_id" not in fields:
        return None

    return LogEvent(**fields)


def load_logs(filepath):
    """
    Reads the given log file and returns a list of LogEvent objects.
    Malformed lines are skipped with a warning. Missing/empty files
    return an empty list (handled safely by utils.safe_read_file).
    """
    raw_lines = utils.safe_read_file(filepath)
    events = []
    skipped = 0

    for line in raw_lines:
        event = _parse_line(line)
        if event is None:
            skipped += 1
            continue
        events.append(event)

    if skipped:
        print(f"[INFO] Skipped {skipped} malformed log line(s).")

    return events
