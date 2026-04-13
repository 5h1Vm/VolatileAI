"""Volatility 3 integration engine — runs plugins and parses output.

Falls back to demo data when Volatility 3 is not installed or no real dump is loaded.
"""

import subprocess
import json
import hashlib
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class EvidenceFile:
    path: str
    filename: str
    size_bytes: int
    size_human: str
    format: str
    md5: str = ""
    sha256: str = ""
    os_profile: str = ""
    is_valid: bool = False


@dataclass
class PluginResult:
    plugin_name: str
    success: bool
    data: List[Dict[str, Any]]
    raw_output: str = ""
    error: str = ""
    row_count: int = 0


class VolatilityEngine:
    """Manages Volatility 3 execution and result parsing."""

    def __init__(self):
        self._vol_available = self._check_volatility()
        self._evidence: Optional[EvidenceFile] = None
        self._results: Dict[str, PluginResult] = {}

    def _check_volatility(self) -> bool:
        try:
            result = subprocess.run(
                ["vol", "--help"],
                capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            try:
                result = subprocess.run(
                    ["python3", "-m", "volatility3", "--help"],
                    capture_output=True, text=True, timeout=10
                )
                return result.returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return False

    @property
    def is_volatility_available(self) -> bool:
        return self._vol_available

    def validate_evidence(self, file_path: str) -> EvidenceFile:
        p = Path(file_path)
        if not p.exists():
            return EvidenceFile(
                path=file_path, filename=p.name, size_bytes=0,
                size_human="N/A", format="unknown", is_valid=False
            )

        size = p.stat().st_size
        size_human = self._human_size(size)
        ext = p.suffix.lower()

        from config import SUPPORTED_FORMATS
        if ext not in SUPPORTED_FORMATS:
            return EvidenceFile(
                path=file_path, filename=p.name, size_bytes=size,
                size_human=size_human, format=ext, is_valid=False
            )

        md5 = self._hash_file(p, "md5")
        sha256 = self._hash_file(p, "sha256")

        self._evidence = EvidenceFile(
            path=str(p.absolute()),
            filename=p.name,
            size_bytes=size,
            size_human=size_human,
            format=ext,
            md5=md5,
            sha256=sha256,
            is_valid=True,
        )
        return self._evidence

    def run_plugin(self, plugin_name: str, file_path: str = None) -> PluginResult:
        path = file_path or (self._evidence.path if self._evidence else None)
        if not path:
            return PluginResult(plugin_name=plugin_name, success=False, data=[], error="No evidence file specified")

        if not self._vol_available:
            return PluginResult(plugin_name=plugin_name, success=False, data=[], error="Volatility 3 not installed")

        try:
            cmd = ["vol", "-f", path, "-r", "json", plugin_name]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode != 0:
                cmd = ["python3", "-m", "volatility3", "-f", path, "-r", "json", plugin_name]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                return PluginResult(
                    plugin_name=plugin_name, success=True,
                    data=data, raw_output=result.stdout,
                    row_count=len(data)
                )
            else:
                return PluginResult(
                    plugin_name=plugin_name, success=False,
                    data=[], error=result.stderr[:500],
                    raw_output=result.stdout
                )
        except subprocess.TimeoutExpired:
            return PluginResult(plugin_name=plugin_name, success=False, data=[], error="Plugin timed out after 300 seconds")
        except json.JSONDecodeError:
            return PluginResult(plugin_name=plugin_name, success=False, data=[], error="Failed to parse JSON output")
        except Exception as e:
            return PluginResult(plugin_name=plugin_name, success=False, data=[], error=str(e))

    def run_all_plugins(self, file_path: str, os_type: str = "windows") -> Dict[str, PluginResult]:
        from config import VOLATILITY_PLUGINS_WINDOWS, VOLATILITY_PLUGINS_LINUX

        plugins = VOLATILITY_PLUGINS_WINDOWS if os_type == "windows" else VOLATILITY_PLUGINS_LINUX
        self._results.clear()

        for plugin in plugins:
            result = self.run_plugin(plugin, file_path)
            self._results[plugin] = result

        return self._results

    def get_results(self) -> Dict[str, PluginResult]:
        return self._results

    def load_demo_results(self, scenario_data: Dict) -> Dict[str, PluginResult]:
        """Load pre-built demo scenario data as if Volatility ran."""
        self._results.clear()
        for plugin_name, data in scenario_data.items():
            self._results[plugin_name] = PluginResult(
                plugin_name=plugin_name,
                success=True,
                data=data if isinstance(data, list) else [],
                row_count=len(data) if isinstance(data, list) else 0,
            )
        return self._results

    def _hash_file(self, path: Path, algo: str = "md5") -> str:
        h = hashlib.new(algo)
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return "unable_to_compute"

    def _human_size(self, size_bytes: int) -> str:
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"
