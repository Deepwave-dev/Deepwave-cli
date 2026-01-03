import json
from pathlib import Path
from typing import Optional

CONFIG_DIR = Path.home() / ".deepwave"
CONFIG_FILE = CONFIG_DIR / "config.json"


def get_config() -> dict:
    """Load CLI configuration."""
    if not CONFIG_FILE.exists():
        return {}
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(config: dict) -> None:
    """Save CLI configuration."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def get_api_url() -> str:
    """Get API base URL from config or environment."""
    config = get_config()
    return config.get("api_url", "https://deepframe.onrender.com")


def get_auth_token() -> Optional[str]:
    """Get authentication token from config."""
    config = get_config()
    return config.get("auth_token")


def set_auth_token(token: str) -> None:
    """Save authentication token."""
    config = get_config()
    config["auth_token"] = token
    save_config(config)
