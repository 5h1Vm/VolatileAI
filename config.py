"""VolatileAI configuration."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
MITRE_DIR = DATA_DIR / "mitre"
DEMO_DIR = DATA_DIR / "demo_scenarios"
CACHE_DIR = DATA_DIR / "cached_responses"
EVIDENCE_DIR = BASE_DIR / "evidence"
REPORTS_DIR = BASE_DIR / "reports" / "output"

APP_NAME = "VolatileAI"
APP_VERSION = "1.0.0"
APP_TAGLINE = "AI-Powered Memory Forensics Investigation Platform"

SUPPORTED_FORMATS = [".raw", ".vmem", ".dmp", ".mem", ".lime", ".img"]

OLLAMA_BASE_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "phi3:mini")

RISK_LEVELS = {
    "critical": {"color": "#ef4444", "bg": "rgba(239,68,68,0.12)", "threshold": 8.0},
    "high":     {"color": "#f97316", "bg": "rgba(249,115,22,0.12)", "threshold": 6.0},
    "medium":   {"color": "#eab308", "bg": "rgba(234,179,8,0.12)", "threshold": 4.0},
    "low":      {"color": "#22c55e", "bg": "rgba(34,197,94,0.12)", "threshold": 0.0},
}

VOLATILITY_PLUGINS_WINDOWS = [
    "windows.pslist", "windows.pstree", "windows.cmdline",
    "windows.dlllist", "windows.netscan", "windows.malfind",
    "windows.handles", "windows.svcscan", "windows.filescan",
    "windows.registry.hivelist",
]

VOLATILITY_PLUGINS_LINUX = [
    "linux.pslist", "linux.pstree", "linux.bash",
    "linux.lsof", "linux.sockstat", "linux.malfind",
    "linux.elfs", "linux.check_syscall",
]

WINDOWS_SYSTEM_PROCESSES = {
    "system": {"expected_path": "", "expected_parent": "idle", "expected_instances": 1},
    "smss.exe": {"expected_path": r"\systemroot\system32\smss.exe", "expected_parent": "system", "expected_instances": 1},
    "csrss.exe": {"expected_path": r"\systemroot\system32\csrss.exe", "expected_parent": "smss.exe", "expected_instances": 2},
    "wininit.exe": {"expected_path": r"\windows\system32\wininit.exe", "expected_parent": "smss.exe", "expected_instances": 1},
    "winlogon.exe": {"expected_path": r"\windows\system32\winlogon.exe", "expected_parent": "smss.exe", "expected_instances": 1},
    "services.exe": {"expected_path": r"\windows\system32\services.exe", "expected_parent": "wininit.exe", "expected_instances": 1},
    "lsass.exe": {"expected_path": r"\windows\system32\lsass.exe", "expected_parent": "wininit.exe", "expected_instances": 1},
    "svchost.exe": {"expected_path": r"\windows\system32\svchost.exe", "expected_parent": "services.exe", "expected_instances": -1},
    "explorer.exe": {"expected_path": r"\windows\explorer.exe", "expected_parent": "userinit.exe", "expected_instances": -1},
    "lsaiso.exe": {"expected_path": r"\windows\system32\lsaiso.exe", "expected_parent": "wininit.exe", "expected_instances": 1},
}

SUSPICIOUS_PARENTS = {
    "cmd.exe": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "iexplore.exe", "firefox.exe", "chrome.exe"],
    "powershell.exe": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mshta.exe", "wscript.exe", "cscript.exe"],
    "mshta.exe": ["winword.exe", "excel.exe", "outlook.exe"],
    "wscript.exe": ["winword.exe", "excel.exe", "outlook.exe"],
    "cscript.exe": ["winword.exe", "excel.exe", "outlook.exe"],
    "regsvr32.exe": ["winword.exe", "excel.exe", "cmd.exe", "powershell.exe"],
    "rundll32.exe": ["winword.exe", "excel.exe", "cmd.exe", "powershell.exe"],
    "certutil.exe": ["cmd.exe", "powershell.exe"],
}

SUSPICIOUS_PORTS = [4444, 5555, 8888, 1337, 31337, 6666, 6667, 9001, 9050, 9051, 12345, 54321]
KNOWN_C2_PORTS = [443, 8443, 8080, 80, 53]

HOMOGLYPH_MAP = {
    "a": ["а", "ɑ"], "c": ["с", "ϲ"], "d": ["ԁ"], "e": ["е", "ε"],
    "i": ["і", "ι"], "o": ["о", "ο"], "p": ["р", "ρ"], "s": ["ѕ", "ꜱ"],
    "x": ["х", "χ"], "y": ["у", "γ"],
}
