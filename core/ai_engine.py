"""AI analysis engine — Ollama integration with caching and RAG."""

import json
import hashlib
import requests
from pathlib import Path
from typing import Dict, List, Optional

from config import OLLAMA_BASE_URL, OLLAMA_MODEL, CACHE_DIR


class AIEngine:
    """Handles AI analysis via Ollama with intelligent caching."""

    def __init__(self):
        self._ollama_available = False
        self._cached_responses: Dict[str, str] = {}
        self._context_data: str = ""
        self._load_cached_responses()

    def check_ollama(self) -> bool:
        try:
            r = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
            self._ollama_available = r.status_code == 200
        except Exception:
            self._ollama_available = False
        return self._ollama_available

    @property
    def is_available(self) -> bool:
        return self._ollama_available

    def set_context(self, findings_summary: str, plugin_data_summary: str):
        self._context_data = f"""You are VolatileAI, an expert memory forensics analyst AI assistant. 
You are analyzing a memory dump and have the following evidence:

=== ANALYSIS FINDINGS ===
{findings_summary}

=== RAW EVIDENCE DATA ===
{plugin_data_summary}

When answering questions:
- Reference specific PIDs, process names, IP addresses, and other concrete evidence
- Map findings to MITRE ATT&CK techniques where applicable
- Provide confidence levels for your assessments
- Suggest follow-up investigation steps
- Be thorough but concise
"""

    def ask(self, question: str, scenario_id: str = "") -> str:
        cache_key = self._make_cache_key(question, scenario_id)
        cached = self._cached_responses.get(cache_key)
        if cached:
            return cached

        fuzzy = self._fuzzy_match(question, scenario_id)
        if fuzzy:
            return fuzzy

        if not self._ollama_available:
            return self._fallback_response(question)

        return self._query_ollama(question)

    def _query_ollama(self, question: str) -> str:
        try:
            prompt = f"{self._context_data}\n\nUser Question: {question}\n\nProvide a detailed forensic analysis response:"

            r = requests.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": 1024,
                    }
                },
                timeout=120,
            )

            if r.status_code == 200:
                data = r.json()
                return data.get("response", "No response generated.")
            return f"Ollama returned status {r.status_code}"

        except requests.Timeout:
            return "AI analysis timed out. The model is taking too long to respond."
        except Exception as e:
            return f"AI engine error: {str(e)}"

    def _make_cache_key(self, question: str, scenario_id: str = "") -> str:
        normalized = question.lower().strip().rstrip("?").strip()
        return f"{scenario_id}:{normalized}" if scenario_id else normalized

    def _fuzzy_match(self, question: str, scenario_id: str = "") -> Optional[str]:
        q_lower = question.lower().strip()
        q_words = set(q_lower.split())

        best_match = None
        best_score = 0

        for key, response in self._cached_responses.items():
            if scenario_id and not key.startswith(scenario_id + ":"):
                if ":" in key and not key.startswith("general:"):
                    continue

            key_clean = key.split(":", 1)[-1] if ":" in key else key
            key_words = set(key_clean.lower().split())

            if not key_words:
                continue

            overlap = len(q_words & key_words)
            score = overlap / max(len(q_words | key_words), 1)

            if score > best_score and score >= 0.45:
                best_score = score
                best_match = response

        return best_match

    def _fallback_response(self, question: str) -> str:
        return (
            "**AI Analysis (Offline Mode)**\n\n"
            "Ollama is not currently running. To enable live AI analysis:\n"
            "1. Install Ollama: `curl -fsSL https://ollama.com/install.sh | sh`\n"
            "2. Pull the model: `ollama pull phi3:mini`\n"
            "3. Start Ollama: `ollama serve`\n\n"
            "Cached responses are still available for demo scenarios."
        )

    def _load_cached_responses(self):
        self._cached_responses.clear()
        if not CACHE_DIR.exists():
            return

        for json_file in CACHE_DIR.glob("*.json"):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    for key, val in data.items():
                        if isinstance(val, dict):
                            val = val.get("response", str(val))
                        self._cached_responses[key.lower().strip()] = str(val)
            except Exception:
                pass

    def get_auto_analysis(self, scenario_id: str = "") -> str:
        return self.ask("Summarize the findings and provide an overall assessment", scenario_id)

    def get_attack_narrative(self, scenario_id: str = "") -> str:
        return self.ask("Reconstruct the complete attack timeline and narrative", scenario_id)

    def get_ioc_list(self, scenario_id: str = "") -> str:
        return self.ask("Generate a complete list of indicators of compromise", scenario_id)

    def get_recommendations(self, scenario_id: str = "") -> str:
        return self.ask("What remediation steps and recommendations do you suggest", scenario_id)
