import os
import json
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, List

class OllamaService:
    """
    Local Ollama LLM client for defensive code auditing, real vulnerability explanations,
    and DPDP Act 2023 compliance remediation.
    Runs 100% locally on localhost:11434 with zero data leakage.
    """

    DEFAULT_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    TIMEOUT = 12

    @classmethod
    def get_base_url(cls) -> str:
        url = os.environ.get("OLLAMA_HOST", cls.DEFAULT_HOST).rstrip("/")
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"http://{url}"
        return url

    @classmethod
    def is_available(cls) -> bool:
        """Check if local Ollama server is running and accessible."""
        try:
            url = f"{cls.get_base_url()}/api/tags"
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                return resp.status == 200
        except Exception:
            return False

    @classmethod
    def get_available_models(cls) -> List[str]:
        """Fetch list of models available in local Ollama instance."""
        try:
            url = f"{cls.get_base_url()}/api/tags"
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                models = [m.get("name", "") for m in data.get("models", [])]
                return [m for m in models if m]
        except Exception:
            return []

    @classmethod
    def get_active_model(cls) -> str:
        """Get preferred model: env OLLAMA_MODEL -> first available local model -> llama3.2:1b."""
        custom = os.environ.get("OLLAMA_MODEL")
        if custom:
            return custom
        available = cls.get_available_models()
        if available:
            return available[0]
        return "llama3.2:1b"

    @classmethod
    def generate(cls, prompt: str, system: Optional[str] = None) -> Optional[str]:
        """Send prompt to local Ollama generate API."""
        if not cls.is_available():
            return None

        model = cls.get_active_model()
        url = f"{cls.get_base_url()}/api/generate"

        payload: Dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.2,
                "top_p": 0.9,
                "num_predict": 250,
            }
        }
        if system:
            payload["system"] = system

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=cls.TIMEOUT) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data.get("response", "").strip()
        except Exception:
            return None
        return None

    @classmethod
    def explain_vulnerability(
        cls,
        title: str,
        file_path: str,
        line_no: int,
        code_snippet: str,
        dpdp_ref: str
    ) -> Optional[str]:
        """
        Ask local Ollama to provide a clear defensive explanation and fix for a vulnerability.
        """
        system = (
            "You are a senior software cybersecurity and India DPDP Act 2023 compliance defense expert. "
            "Your job is to provide defensive code remediation. Be concise, actionable, and practical in 2-3 sentences."
        )
        prompt = (
            f"Vulnerability Title: {title}\n"
            f"File: {file_path}:{line_no}\n"
            f"Statutory DPDP Reference: {dpdp_ref}\n"
            f"Vulnerable Code: {code_snippet[:120]}\n\n"
            "Provide a concise defensive explanation: (1) why this code flaw is dangerous, "
            "and (2) the exact secure pattern developers must use to fix it."
        )
        return cls.generate(prompt, system=system)
