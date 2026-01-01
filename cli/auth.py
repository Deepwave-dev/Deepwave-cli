import time
import httpx


def device_code_flow(api_url: str) -> str:
    """Device code OAuth flow for authentication."""
    timeout = httpx.Timeout(180.0, connect=10.0)
    with httpx.Client(timeout=timeout) as client:
        response = client.post(f"{api_url}/api/v1/auth/device-code")
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

            token_response = client.post(f"{api_url}/api/v1/auth/device-token", json={"device_code": device_code})

            if token_response.status_code == 200:
                token_data = token_response.json()
                return token_data["access_token"]
            elif token_response.status_code == 400:
                error_data = token_response.json()
                error_detail = error_data.get("detail", "")

                if error_detail == "authorization_pending":
                    print(".", end="", flush=True)
                    continue
                else:
                    raise Exception(error_detail)
            else:
                token_response.raise_for_status()

        raise Exception("Authentication timed out")


def login_with_token(token: str, api_url: str) -> bool:
    """Login with provided token."""
    timeout = httpx.Timeout(180.0, connect=10.0)
    with httpx.Client(timeout=timeout) as client:
        response = client.get(f"{api_url}/api/v1/auth/verify", headers={"Authorization": f"Bearer {token}"})
        return response.status_code == 200
