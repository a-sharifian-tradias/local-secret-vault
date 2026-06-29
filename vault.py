import argparse
import datetime as dt
import getpass
import json
import os
import secrets as secrets_module
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Tuple

from local_vault.client import api_request, delete_server_state, is_server_running
from local_vault.constants import (
    DEFAULT_HOST,
    SERVER_STATE_FILE,
    VAULT_FILE,
)
from local_vault.crypto import (
    decrypt_vault,
    rewrite_vault_with_new_password,
    write_new_vault,
    write_vault_with_key,
)
from local_vault.env_parser import (
    normalize_name_affix,
    parse_env_lines,
    read_env_paste_until_end,
    transform_secret_name,
    validate_secret_name,
)
from local_vault.errors import VaultError
from local_vault.storage import atomic_write_json, ensure_vault_home, read_json
from local_vault.time_utils import iso_utc, parse_iso_utc, utc_now


def get_free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((DEFAULT_HOST, 0))
        return int(sock.getsockname()[1])


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


def command_init(args: argparse.Namespace) -> int:
    ensure_vault_home()

    if VAULT_FILE.exists():
        print(f"Vault already exists: {VAULT_FILE}")
        return 1

    password_1 = getpass.getpass("Create master password: ")
    password_2 = getpass.getpass("Confirm master password: ")

    if not password_1:
        print("Master password cannot be empty.")
        return 1

    if password_1 != password_2:
        print("Passwords do not match.")
        return 1

    write_new_vault(password_1)
    print(f"Initialized encrypted vault: {VAULT_FILE}")
    print("If you forget the master password, the secrets cannot be recovered.")
    return 0


def command_change_password(args: argparse.Namespace) -> int:
    ensure_vault_home()

    if is_server_running():
        print("Vault is currently unlocked.")
        print("Run this first: vault lock")
        print("Then run: vault change-password")
        return 1

    if not VAULT_FILE.exists():
        print(f"Vault does not exist yet: {VAULT_FILE}")
        print("Run: vault init")
        return 1

    current_password = getpass.getpass("Current master password: ")

    try:
        secrets_dict, _old_key = decrypt_vault(current_password)
    except VaultError as exc:
        print(str(exc))
        return 1

    new_password_1 = getpass.getpass("New master password: ")
    new_password_2 = getpass.getpass("Confirm new master password: ")

    if not new_password_1:
        print("New master password cannot be empty.")
        return 1

    if new_password_1 != new_password_2:
        print("New passwords do not match.")
        return 1

    if new_password_1 == current_password:
        print("New master password must be different from the current master password.")
        return 1

    confirmation = input("Type CHANGE PASSWORD to re-encrypt the vault with the new password: ")

    if confirmation != "CHANGE PASSWORD":
        print("Cancelled.")
        return 1

    rewrite_vault_with_new_password(secrets_dict, new_password_1)
    delete_server_state()

    print("Master password changed.")
    print("The vault has been re-encrypted with a new salt and key.")
    print("Run: vault unlock --hours 8")
    return 0


def command_unlock(args: argparse.Namespace) -> int:
    ensure_vault_home()

    if is_server_running():
        print("Vault is already unlocked.")
        return 0

    if args.hours <= 0:
        print("--hours must be greater than 0.")
        return 1

    master_password = getpass.getpass("Master password: ")

    try:
        secrets_dict, fernet_key = decrypt_vault(master_password)
    except VaultError as exc:
        print(str(exc))
        return 1

    host = DEFAULT_HOST
    port = get_free_local_port()
    token = secrets_module.token_urlsafe(32)
    expires_at = utc_now() + dt.timedelta(hours=args.hours)

    bootstrap = {
        "host": host,
        "port": port,
        "token": token,
        "expires_at": iso_utc(expires_at),
        "secrets": secrets_dict,
        "fernet_key_b64": fernet_key.decode("utf-8"),
    }

    creationflags = 0
    startupinfo = None

    if os.name == "nt":
        creationflags = subprocess.CREATE_NO_WINDOW
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0

    process = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "_serve"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        creationflags=creationflags,
        startupinfo=startupinfo,
    )

    assert process.stdin is not None
    process.stdin.write(json.dumps(bootstrap))
    process.stdin.close()

    state = {
        "host": host,
        "port": port,
        "pid": process.pid,
        "token": token,
        "expires_at": iso_utc(expires_at),
    }

    atomic_write_json(SERVER_STATE_FILE, state)

    for _ in range(30):
        time.sleep(0.1)
        if is_server_running():
            print(f"Vault unlocked until {expires_at.astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}.")
            print(f"Local server: http://{host}:{port}")
            return 0

    delete_server_state()
    print("Failed to start vault server.")
    return 1


def command_lock(args: argparse.Namespace) -> int:
    try:
        api_request("/lock", {})
        print("Vault locked.")
        return 0
    except VaultError:
        delete_server_state()
        print("Vault is locked.")
        return 0


def command_status(args: argparse.Namespace) -> int:
    try:
        result = api_request("/status")
    except VaultError as exc:
        print(str(exc))
        return 1

    expires_at = parse_iso_utc(result["expires_at"]).astimezone()
    seconds_left = int(result["seconds_left"])
    secret_count = int(result["secret_count"])

    print("Status: unlocked")
    print(f"Expires at: {expires_at.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    print(f"Seconds left: {seconds_left}")
    print(f"Secret count: {secret_count}")
    return 0


def command_list(args: argparse.Namespace) -> int:
    try:
        result = api_request("/list", {})
    except VaultError as exc:
        print(str(exc))
        return 1

    names = result.get("names", [])

    if not names:
        print("No secrets stored.")
        return 0

    for name in names:
        print(name)

    return 0


def command_set(args: argparse.Namespace) -> int:
    name = args.name

    try:
        validate_secret_name(name)
    except VaultError as exc:
        print(str(exc))
        return 1

    value = getpass.getpass(f"Secret value for {name}: ")

    if value == "":
        confirm = input("Secret value is empty. Store empty value? Type YES to confirm: ")
        if confirm != "YES":
            print("Cancelled.")
            return 1

    try:
        api_request("/set", {"name": name, "value": value})
    except VaultError as exc:
        print(str(exc))
        return 1

    print(f"Stored secret: {name}")
    return 0


def command_delete(args: argparse.Namespace) -> int:
    name = args.name

    try:
        validate_secret_name(name)
    except VaultError as exc:
        print(str(exc))
        return 1

    print(f"This will permanently delete secret: {name}")
    confirmation = input(f"Type DELETE {name} to confirm: ")

    if confirmation != f"DELETE {name}":
        print("Cancelled.")
        return 1

    try:
        api_request("/delete", {"name": name})
    except VaultError as exc:
        print(str(exc))
        return 1

    print(f"Deleted secret: {name}")
    return 0


def command_rename(args: argparse.Namespace) -> int:
    old_name = args.old_name
    new_name = args.new_name

    try:
        validate_secret_name(old_name)
        validate_secret_name(new_name)
    except VaultError as exc:
        print(str(exc))
        return 1

    if old_name == new_name:
        print("Old and new secret names are the same. Nothing to rename.")
        return 0

    if args.overwrite:
        print(f"This will rename {old_name} to {new_name} and overwrite {new_name} if it exists.")
        confirmation = input(f"Type RENAME {old_name} TO {new_name} to confirm: ")

        if confirmation != f"RENAME {old_name} TO {new_name}":
            print("Cancelled.")
            return 1

    try:
        api_request(
            "/rename",
            {
                "old_name": old_name,
                "new_name": new_name,
                "overwrite": args.overwrite,
            },
        )
    except VaultError as exc:
        print(str(exc))
        return 1

    print(f"Renamed secret: {old_name} -> {new_name}")
    return 0


def command_import_env(args: argparse.Namespace) -> int:
    prefix = args.prefix
    suffix = args.suffix

    try:
        prefix = normalize_name_affix(prefix)
    except VaultError as exc:
        print(f"Invalid prefix: {exc}")
        return 1

    try:
        suffix = normalize_name_affix(suffix)
    except VaultError as exc:
        print(f"Invalid suffix: {exc}")
        return 1

    lines = read_env_paste_until_end()

    try:
        parsed = parse_env_lines(lines)
    except VaultError as exc:
        print(str(exc))
        return 1

    if not parsed:
        print("No variables found.")
        return 1

    transformed: Dict[str, str] = {}

    try:
        for original_name, value in parsed.items():
            transformed_name = transform_secret_name(original_name, prefix, suffix)
            transformed[transformed_name] = value
    except VaultError as exc:
        print(str(exc))
        return 1

    names = sorted(transformed.keys())

    if args.dry_run:
        print("Dry run. No secrets were stored.")
        print("Would import these secret names:")
        for name in names:
            print(name)
        return 0

    try:
        existing_result = api_request("/list", {})
    except VaultError as exc:
        print(str(exc))
        return 1

    existing_names = set(existing_result.get("names", []))
    conflicts = sorted(name for name in names if name in existing_names)

    if conflicts and not args.overwrite:
        print("These secrets already exist:")
        for name in conflicts:
            print(name)
        print()
        print("Nothing was imported.")
        print("Run again with --overwrite if you really want to replace existing values.")
        return 1

    print("About to import these secret names:")
    for name in names:
        print(name)

    print()
    print(f"Count: {len(names)}")
    print("Secret values will not be printed.")

    if args.overwrite and conflicts:
        confirmation = input("Type IMPORT OVERWRITE to store these secrets and overwrite conflicts: ")
        if confirmation != "IMPORT OVERWRITE":
            print("Cancelled.")
            return 1
    else:
        confirmation = input("Type IMPORT to store these secrets: ")
        if confirmation != "IMPORT":
            print("Cancelled.")
            return 1

    try:
        result = api_request(
            "/set-many",
            {
                "secrets": transformed,
                "overwrite": args.overwrite,
            },
        )
    except VaultError as exc:
        print(str(exc))
        return 1

    stored = result.get("stored", names)

    print("Imported secret names:")
    for name in stored:
        print(name)

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vault", description="Local encrypted secrets vault.")
    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser("init", help="Initialize a new encrypted vault.")
    init_parser.set_defaults(func=command_init)

    change_password_parser = subparsers.add_parser("change-password", help="Change the vault master password.")
    change_password_parser.set_defaults(func=command_change_password)

    unlock_parser = subparsers.add_parser("unlock", help="Unlock vault for a limited time.")
    unlock_parser.add_argument("--hours", type=float, default=8, help="Number of hours to keep vault unlocked.")
    unlock_parser.set_defaults(func=command_unlock)

    lock_parser = subparsers.add_parser("lock", help="Lock the vault immediately.")
    lock_parser.set_defaults(func=command_lock)

    status_parser = subparsers.add_parser("status", help="Show vault status.")
    status_parser.set_defaults(func=command_status)

    list_parser = subparsers.add_parser("list", help="List secret names only.")
    list_parser.set_defaults(func=command_list)

    set_parser = subparsers.add_parser("set", help="Store or update a secret.")
    set_parser.add_argument("name", help="Secret name, for example DATABASE_URL.")
    set_parser.set_defaults(func=command_set)

    delete_parser = subparsers.add_parser("delete", help="Delete a secret from the vault.")
    delete_parser.add_argument("name", help="Secret name to delete, for example OLD_API_KEY.")
    delete_parser.set_defaults(func=command_delete)

    rename_parser = subparsers.add_parser("rename", help="Rename a secret without printing its value.")
    rename_parser.add_argument("old_name", help="Existing secret name.")
    rename_parser.add_argument("new_name", help="New secret name.")
    rename_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite the target secret if it already exists.",
    )
    rename_parser.set_defaults(func=command_rename)

    import_env_parser = subparsers.add_parser("import-env", help="Paste .env content and import it into the vault.")
    import_env_parser.add_argument("--prefix", help="Prefix to add to every imported secret name.")
    import_env_parser.add_argument("--suffix", help="Suffix to add to every imported secret name.")
    import_env_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and show names only. Do not store anything.",
    )
    import_env_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing secrets with imported values.",
    )
    import_env_parser.set_defaults(func=command_import_env)

    return parser


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "_serve":
        run_server_from_stdin()
        return 0

    parser = build_parser()

    if len(sys.argv) == 1:
        parser.print_help()
        return 0

    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        return 0

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print()
        print("Cancelled.")
        return 130
    except VaultError as exc:
        print(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())