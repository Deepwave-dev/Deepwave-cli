"""
File exclusion and language detection utilities.
"""

from pathlib import Path
from typing import Dict

# Language mapping
LANGUAGE_MAP: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".cpp": "cpp",
    ".c": "c",
    ".cs": "csharp",
    ".php": "php",
    ".rb": "ruby",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
    ".clj": "clojure",
    ".hs": "haskell",
    ".ml": "ocaml",
    ".fs": "fsharp",
    ".r": "r",
    ".m": "matlab",
    ".sh": "shell",
    ".bash": "bash",
    ".zsh": "zsh",
    ".fish": "fish",
    ".ps1": "powershell",
    ".bat": "batch",
    ".cmd": "batch",
    ".sql": "sql",
    ".html": "html",
    ".css": "css",
    ".scss": "scss",
    ".sass": "sass",
    ".less": "less",
    ".xml": "xml",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".ini": "ini",
    ".cfg": "config",
    ".conf": "config",
    ".txt": "text",
    ".md": "markdown",
    ".rst": "restructuredtext",
    ".tex": "latex",
    ".dockerfile": "dockerfile",
    ".dockerignore": "dockerignore",
    ".gitignore": "gitignore",
    ".env": "environment",
    ".env.local": "environment",
    ".env.production": "environment",
    ".env.development": "environment",
}


def is_excluded(file_path: Path) -> bool:
    """Check if file path should be excluded (hardcoded default excludes)"""
    path_str = str(file_path)
    default_excludes = ["venv", "node_modules", ".git", "__pycache__", ".idea", ".vscode"]
    if any(excluded in path_str for excluded in default_excludes):
        return True

    # Exclude generated files and lock files
    filename = file_path.name.lower()
    excluded_files = [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "graph.json",
        "stats.json",
        "manifest.json",
        "chunks.jsonl",
    ]
    if filename in excluded_files:
        return True

    # Exclude binary files (images, etc.)
    binary_extensions = {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".svg",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
    }
    if file_path.suffix.lower() in binary_extensions:
        return True

    return False


def detect_language(file_path: Path) -> str:
    """Detect language from file path"""
    return LANGUAGE_MAP.get(file_path.suffix.lower(), "unknown")


def count_lines(file_path: Path) -> int:
    """Count lines in file path"""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def is_test_file(file_path: Path) -> bool:
    """Check if file is a test file."""
    path_parts = file_path.parts
    if "test" in path_parts or "tests" in path_parts:
        return True
    filename = file_path.name
    return filename.startswith("test_") or filename.endswith("_test.py")


def discover_python_files(root: Path, exclude_tests: bool = False) -> list[Path]:
    """Discover Python files, excluding common non-source directories and test files."""
    python_files = []
    for py_file in root.rglob("*.py"):
        # Skip hidden directories
        if any(part.startswith(".") for part in py_file.parts):
            continue
        # Skip common non-source directories
        if any(excluded in py_file.parts for excluded in ("venv", "node_modules", "__pycache__")):
            continue
        # Optionally skip test files
        if exclude_tests and is_test_file(py_file):
            continue
        python_files.append(py_file)
    return python_files


def file_to_module_path(file_path: Path, project_root: Path) -> str:
    """Convert file path to Python module path."""
    try:
        rel_path = file_path.relative_to(project_root)
    except ValueError:
        rel_path = file_path
    path_str = str(rel_path)
    if path_str.endswith("/__init__.py"):
        path_str = path_str[: -len("/__init__.py")]
    elif path_str.endswith(".py"):
        path_str = path_str[: -len(".py")]
    return path_str.replace("/", ".").replace("\\", ".")
