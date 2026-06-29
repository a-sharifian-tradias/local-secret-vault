from __future__ import annotations

import json
from typing import Any, Dict
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

from local_vault.constants import SERVER_STATE_FILE
from local_vault.errors import VaultError
from local_vault.storage import read_json


def read_server_state() -> Dict[str, Any]:
    if not SERVER_STATE_FILE.exists():
        raise VaultError("Vault is locked. Run: vault unlock --hours 8")
    return read_json(SERVER_STATE_FILE)


def delete_server_state() -> None:
    try:
        SERVER_STATE_FILE.unlink()
    except FileNotFoundError:
        pass


def api_request(
    path: str,
    payload: Dict[str, Any] | None = None,
    timeout_seconds: float = 3.0,
) -> Dict[str, Any]:
    state = read_server_state()

    host = state["host"]
    port = int(state["port"])
    token = state["token"]

    url = f"http://{host}:{port}{path}"

    body = None
    method = "GET"

    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        method = "POST"

    req = urllib_request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib_request.urlopen(req, timeout=timeout_seconds) as response:
            response_body = response.read().decode("utf-8")
            if not response_body:
                return {}
            return json.loads(response_body)
    except HTTPError as exc:
        error_text = exc.read().decode("utf-8", errors="replace")
        try:
            error_data = json.loads(error_text)
            message = error_data.get("error", error_text)
        except json.JSONDecodeError:
            message = error_text
        raise VaultError(message) from exc
    except URLError as exc:
        delete_server_state()
        raise VaultError(
            "Vault appears to be locked or the unlock server is not reachable. Run: vault unlock --hours 8"
        ) from exc
    except TimeoutError as exc:
        raise VaultError("Vault server timed out.") from exc


def is_server_running() -> bool:
    try:
        result = api_request("/status", None, timeout_seconds=1.0)
        return result.get("status") == "unlocked"
    except Exception:
        return False