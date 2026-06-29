from __future__ import annotations

import datetime as dt
import json
import secrets as secrets_module
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Tuple

from local_vault.client import delete_server_state
from local_vault.constants import VAULT_FILE
from local_vault.storage import read_json
from local_vault.time_utils import iso_utc, parse_iso_utc, utc_now
from local_vault.crypto import write_vault_with_key


class VaultHTTPHandler(BaseHTTPRequestHandler):
    server_version = "LocalSecretVault/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, status_code: int, payload: Dict[str, Any]) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def _is_expired(self) -> bool:
        return utc_now() >= self.server.expires_at

    def _authorize(self) -> bool:
        auth_header = self.headers.get("Authorization", "")
        expected = f"Bearer {self.server.token}"
        return secrets_module.compare_digest(auth_header, expected)

    def _require_ready(self) -> bool:
        if not self._authorize():
            self._send_json(401, {"error": "Unauthorized vault request."})
            return False

        if self._is_expired():
            self._send_json(423, {"error": "Vault is locked. Run: vault unlock --hours 8"})
            delete_server_state()
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return False

        return True

    def do_GET(self) -> None:
        if self.path != "/status":
            self._send_json(404, {"error": "Unknown endpoint."})
            return

        if not self._require_ready():
            return

        seconds_left = max(0, int((self.server.expires_at - utc_now()).total_seconds()))

        self._send_json(
            200,
            {
                "status": "unlocked",
                "expires_at": iso_utc(self.server.expires_at),
                "seconds_left": seconds_left,
                "secret_count": len(self.server.secrets_dict),
            },
        )

    def do_POST(self) -> None:
        if not self._require_ready():
            return

        try:
            payload = self._read_json_body()
        except Exception:
            self._send_json(400, {"error": "Invalid JSON request."})
            return

        if self.path == "/get":
            names = payload.get("names", [])
            if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
                self._send_json(400, {"error": "Request field 'names' must be a list of strings."})
                return

            found = {}
            missing = []

            for name in names:
                if name in self.server.secrets_dict:
                    found[name] = self.server.secrets_dict[name]
                else:
                    missing.append(name)

            self._send_json(200, {"secrets": found, "missing": missing})
            return

        if self.path == "/list":
            names = sorted(self.server.secrets_dict.keys())
            self._send_json(200, {"names": names})
            return

        if self.path == "/set":
            name = payload.get("name")
            value = payload.get("value")

            if not isinstance(name, str) or not name:
                self._send_json(400, {"error": "Secret name must be a non-empty string."})
                return

            if not isinstance(value, str):
                self._send_json(400, {"error": "Secret value must be a string."})
                return

            self.server.secrets_dict[name] = value

            existing_vault_data = read_json(VAULT_FILE)
            write_vault_with_key(
                self.server.secrets_dict,
                self.server.fernet_key,
                existing_vault_data,
            )

            self._send_json(200, {"ok": True, "name": name})
            return

        if self.path == "/set-many":
            incoming = payload.get("secrets")
            overwrite = bool(payload.get("overwrite", False))

            if not isinstance(incoming, dict):
                self._send_json(400, {"error": "Request field 'secrets' must be an object."})
                return

            clean_incoming: Dict[str, str] = {}

            for name, value in incoming.items():
                if not isinstance(name, str) or not name:
                    self._send_json(400, {"error": "All secret names must be non-empty strings."})
                    return

                if not isinstance(value, str):
                    self._send_json(400, {"error": f"Secret value must be a string: {name}"})
                    return

                clean_incoming[name] = value

            conflicts = sorted(name for name in clean_incoming if name in self.server.secrets_dict)

            if conflicts and not overwrite:
                self._send_json(
                    409,
                    {
                        "error": "Some secrets already exist. Use --overwrite if you really want to replace them.",
                        "conflicts": conflicts,
                    },
                )
                return

            self.server.secrets_dict.update(clean_incoming)

            existing_vault_data = read_json(VAULT_FILE)
            write_vault_with_key(
                self.server.secrets_dict,
                self.server.fernet_key,
                existing_vault_data,
            )

            self._send_json(200, {"ok": True, "stored": sorted(clean_incoming.keys())})
            return

        if self.path == "/delete":
            name = payload.get("name")

            if not isinstance(name, str) or not name:
                self._send_json(400, {"error": "Secret name must be a non-empty string."})
                return

            if name not in self.server.secrets_dict:
                self._send_json(404, {"error": f"Secret does not exist: {name}"})
                return

            del self.server.secrets_dict[name]

            existing_vault_data = read_json(VAULT_FILE)
            write_vault_with_key(
                self.server.secrets_dict,
                self.server.fernet_key,
                existing_vault_data,
            )

            self._send_json(200, {"ok": True, "deleted": name})
            return

        if self.path == "/rename":
            old_name = payload.get("old_name")
            new_name = payload.get("new_name")
            overwrite = bool(payload.get("overwrite", False))

            if not isinstance(old_name, str) or not old_name:
                self._send_json(400, {"error": "Old secret name must be a non-empty string."})
                return

            if not isinstance(new_name, str) or not new_name:
                self._send_json(400, {"error": "New secret name must be a non-empty string."})
                return

            if old_name not in self.server.secrets_dict:
                self._send_json(404, {"error": f"Secret does not exist: {old_name}"})
                return

            if new_name in self.server.secrets_dict and not overwrite:
                self._send_json(
                    409,
                    {
                        "error": (
                            f"Target secret already exists: {new_name}. "
                            f"Use --overwrite if you really want to replace it."
                        )
                    },
                )
                return

            self.server.secrets_dict[new_name] = self.server.secrets_dict[old_name]

            if old_name != new_name:
                del self.server.secrets_dict[old_name]

            existing_vault_data = read_json(VAULT_FILE)
            write_vault_with_key(
                self.server.secrets_dict,
                self.server.fernet_key,
                existing_vault_data,
            )

            self._send_json(200, {"ok": True, "old_name": old_name, "new_name": new_name})
            return

        if self.path == "/lock":
            self.server.secrets_dict.clear()
            self.server.fernet_key = None
            delete_server_state()

            self._send_json(200, {"ok": True, "status": "locked"})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return

        self._send_json(404, {"error": "Unknown endpoint."})


class VaultHTTPServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: Tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        secrets_dict: Dict[str, str],
        fernet_key: bytes,
        token: str,
        expires_at: dt.datetime,
    ) -> None:
        super().__init__(server_address, handler_class)
        self.secrets_dict = secrets_dict
        self.fernet_key = fernet_key
        self.token = token
        self.expires_at = expires_at


def run_server_from_stdin() -> None:
    raw = sys.stdin.read()
    bootstrap = json.loads(raw)

    host = bootstrap["host"]
    port = int(bootstrap["port"])
    token = bootstrap["token"]
    expires_at = parse_iso_utc(bootstrap["expires_at"])
    secrets_dict = bootstrap["secrets"]
    fernet_key = bootstrap["fernet_key_b64"].encode("utf-8")

    httpd = VaultHTTPServer(
        (host, port),
        VaultHTTPHandler,
        secrets_dict=secrets_dict,
        fernet_key=fernet_key,
        token=token,
        expires_at=expires_at,
    )

    def auto_shutdown() -> None:
        seconds = max(0, int((expires_at - utc_now()).total_seconds()))
        time.sleep(seconds)
        try:
            httpd.secrets_dict.clear()
            httpd.fernet_key = None
            delete_server_state()
            httpd.shutdown()
        except Exception:
            pass

    threading.Thread(target=auto_shutdown, daemon=True).start()

    httpd.serve_forever(poll_interval=1.0)
    httpd.server_close()
