"""
utils.py
--------
Shared helper functions used across the SOC Incident Analyzer.

Responsibilities:
    - Safe file reading (never crash the app on missing/empty files)
    - Safe JSON loading (never crash on missing/invalid JSON)
    - Loading application configuration (config.json)
    - Console formatting helpers (headers, dividers)
    - Small validation helpers for user input
"""

import json
import os

# Default configuration used if config.json is missing or invalid.
# This keeps the application running even with a damaged config file.
DEFAULT_CONFIG = {
    "risk_thresholds": {
        "low_max": 5,
        "medium_max": 15,
        "high_max": 30
    },
    "timeline_window_seconds": 60,
    "brute_force_threshold": 3,
    "file_paths": {
        "sample_logs": "sample_logs.txt",
        "mitre_mapping": "mitre_mapping.json",
        "incident_report": "incident_report.txt"
    }
}


def safe_read_file(filepath):
    """
    Reads a text file and returns its lines as a list of strings.
    Returns an empty list (never raises) if the file is missing or empty.
    """
    if not os.path.exists(filepath):
        print(f"[WARNING] File not found: {filepath}")
        return []

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
        if not lines:
            print(f"[WARNING] File is empty: {filepath}")
        return lines
    except (IOError, OSError) as e:
        print(f"[ERROR] Could not read file '{filepath}': {e}")
        return []


def safe_load_json(filepath, fallback=None):
    """
    Loads a JSON file and returns it as a Python dict.
    Returns 'fallback' (or an empty dict) if the file is missing or invalid.
    """
    if fallback is None:
        fallback = {}

    if not os.path.exists(filepath):
        print(f"[WARNING] JSON file not found: {filepath}")
        return fallback

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError, OSError) as e:
        print(f"[ERROR] Could not load JSON file '{filepath}': {e}")
        return fallback


def load_config(filepath="config.json"):
    """
    Loads application configuration from config.json.
    Falls back to DEFAULT_CONFIG (fully or partially) if the file
    is missing, invalid, or incomplete.
    """
    loaded = safe_load_json(filepath, fallback=None)

    if not loaded:
        print("[INFO] Using built-in default configuration.")
        return DEFAULT_CONFIG

    # Merge loaded config over the defaults so missing keys never break the app
    config = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy of defaults
    for key, value in loaded.items():
        if isinstance(value, dict) and key in config:
            config[key].update(value)
        else:
            config[key] = value

    return config


def print_header(title, width=52, char="="):
    """Prints a centered header surrounded by a divider line."""
    print(char * width)
    print(title.center(width))
    print(char * width)


def print_divider(width=52, char="-"):
    """Prints a simple divider line."""
    print(char * width)


def is_valid_event_id(value):
    """Returns True if the given string is a valid numeric Event ID."""
    return value.strip().isdigit()


def safe_int(value, default=0):
    """Converts a value to int, returning a default on failure."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
