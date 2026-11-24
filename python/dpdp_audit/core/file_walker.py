import os
import re
from pathlib import Path
from typing import Generator, Set
import yaml

IGNORE_DIRS = {
    "node_modules", ".git", "dist", "build", ".venv", "venv", "env",
    "coverage", ".next", ".nuxt", ".turbo", "__pycache__", ".pytest_cache",
    ".cache", ".idea", ".vscode"
}

IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip", ".tar", ".gz",
    ".lock", ".map", ".pyc", ".pyo", ".bin", ".exe", ".so", ".dylib"
}

IGNORE_FILENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Pipfile.lock", "Cargo.lock", "composer.lock"
}

class FileWalker:
    """Fast, safe directory walker with ignore rules and comment-level suppression."""

    @classmethod
    def walk(cls, root_path: str, max_files: int = 25000) -> Generator[Path, None, None]:
        root = Path(root_path).resolve()
        count = 0

        # Load .dpdp-audit.yaml or .dpdprc.yaml if exists
        custom_ignores = cls._load_project_config(root)

        for dirpath, dirnames, filenames in os.walk(root):
            # Prune ignored directory trees in-place
            dirnames[:] = [
                d for d in dirnames
                if d not in IGNORE_DIRS and d not in custom_ignores and not d.startswith(".cache")
            ]

            for fname in filenames:
                if fname in IGNORE_FILENAMES or fname.endswith(".min.js") or fname.endswith(".min.css"):
                    continue

                file_path = Path(dirpath) / fname
                ext = file_path.suffix.lower()

                if ext in IGNORE_EXTENSIONS:
                    continue

                # Relative path match against custom ignores
                rel_path = str(file_path.relative_to(root))
                if any(rel_path.startswith(ig) for ig in custom_ignores):
                    continue

                # Skip files larger than 1MB (minified bundles, dumps)
                try:
                    if file_path.stat().st_size > 1024 * 1024:
                        continue
                except OSError:
                    continue

                yield file_path
                count += 1
                if count >= max_files:
                    return

    @classmethod
    def _load_project_config(cls, root: Path) -> Set[str]:
        for cfg_name in [".dpdp-audit.yaml", ".dpdp-audit.yml", ".dpdprc.yaml", ".dpdprc.json"]:
            cfg_file = root / cfg_name
            if cfg_file.exists():
                try:
                    with open(cfg_file, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                        if isinstance(data, dict):
                            return set(data.get("ignore", []))
                except Exception:
                    pass
        return set()

    @classmethod
    def has_ignore_comment(cls, line_content: str, rule_id: str) -> bool:
        """
        Check if line contains inline suppression comment:
        // dpdp-ignore: DPDP-LOG-001 reason or # dpdp-ignore: DPDP-LOG-001
        """
        pattern = rf"(?://|#|/\*)\s*dpdp-ignore:\s*({re.escape(rule_id)}|ALL)"
        return bool(re.search(pattern, line_content, re.IGNORECASE))
