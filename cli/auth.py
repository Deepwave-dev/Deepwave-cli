"""Authentication utilities."""

import time
import requests
from typing import Optional

from .config import get_api_url, set_auth_token


def device_code_flow(api_url: str) -> str:
    """Device code OAuth flow for authentication."""
    try:
        response = requests.post(f"{api_url}/api/v1/auth/device-code", timeout=10)
        if response.status_code == 404:
            raise NotImplementedError("Device code endpoint not available on backend")
        response.raise_for_status()
        data = response.json()

        device_code = data["device_code"]
        user_code = data["user_code"]
        verification_uri = data["verification_uri"]
        interval = data.get("interval", 5)
        expires_in = data.get("expires_in", 600)

        print(f"\n🔐 Device Code Authentication")
        print(f"   Visit: {verification_uri}")
        print(f"   Enter code: {user_code}")
        print(f"\n⏳ Waiting for authentication...")

        start_time = time.time()
        while time.time() - start_time < expires_in:
            time.sleep(interval)

            token_response = requests.post(
                f"{api_url}/api/v1/auth/device-token", json={"device_code": device_code}, timeout=10
            )

            if token_response.status_code == 200:
                token_data = token_response.json()
                return token_data["access_token"]
            elif token_response.status_code == 400:
                error_data = token_response.json()
                if error_data.get("error") == "authorization_pending":
                    print(".", end="", flush=True)
                    continue
                else:
                    raise ValueError(f"Authentication failed: {error_data.get('error_description', 'Unknown error')}")
            else:
                token_response.raise_for_status()

        raise TimeoutError("Authentication timed out. Please try again.")

    except requests.exceptions.ConnectionError:
        raise ConnectionError(f"Failed to connect to API at {api_url}")
    except requests.exceptions.RequestException as e:
        if "404" in str(e) or "Not Found" in str(e):
            raise NotImplementedError("Device code endpoint not available on backend")
        raise ConnectionError(f"API request failed: {e}")
    except KeyError as e:
        raise ValueError(f"Invalid response from server: missing {e}")


def login_with_token(token: str, api_url: str) -> bool:
    """Login with provided token."""
    try:
        response = requests.get(
            f"{api_url}/api/v1/system/health", headers={"Authorization": f"Bearer {token}"}, timeout=10
        )
        return response.status_code == 200
    except Exception:
        return False
