from pathlib import Path


HIGH_RISK_EXTENSIONS = {
    ".Exe",
    ".dll",
    ".sys",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".scr"
}

MEDIUM_RISK_EXTENSIONS = {
    ".py",
    ".js",
    ".jar"
    ".msi"
    ".reg"
}

def calculate_severity(file_path, event_type):
    extension = Path(file_path).suffix.lower()

    if extension in HIGH_RISK_EXTENSIONS:
        return "CRITICAL"

    if extension in MEDIUM_RISK_EXTENSIONS:
        return "HIGH"

    if event_type == "DELETED":
        return "HIGH"

    if event_type == "MODIFIED":
        return "HIGH"

    return "MEDIUM"

    