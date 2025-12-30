from pathlib import Path
from typing import List
from loguru import logger

from engine.ignore import discover_python_files


class FrameworkDetector:
    """Detects the framework used in a repository."""

    def detect(self, project_path: Path) -> str:
        """Detect framework used in projects, returns 'fastapi', 'django', or 'unknown'."""
        # Check dependency files first
        framework = self._check_dependencies(project_path)
        if framework:
            return framework

        # Fallback to scanning imports in Python files
        return self._scan_imports(project_path)

    def _check_dependencies(self, project_path: Path) -> str:
        """Check requirements.txt, pyproject.toml, etc."""

        # Check requirements.txt
        req_file = project_path / "requirements.txt"
        if req_file.exists():
            try:
                content = req_file.read_text().lower()
                if "django" in content:
                    return "django"
                if "fastapi" in content:
                    return "fastapi"
            except Exception:
                pass

        # Check pyproject.toml
        pyproject = project_path / "pyproject.toml"
        if pyproject.exists():
            try:
                content = pyproject.read_text().lower()
                if "django" in content:
                    return "django"
                if "fastapi" in content:
                    return "fastapi"
            except Exception:
                pass

        return None

    def _scan_imports(self, project_path: Path) -> str:
        """Scan Python files for known framework imports."""
        python_files = discover_python_files(project_path)
        for file_path in python_files:
            try:
                content = file_path.read_text()
                if "from fastapi" in content or "import fastapi" in content:
                    return "fastapi"
                if "from django" in content or "import django" in content:
                    return "django"
            except Exception:
                pass

        return "unknown"
