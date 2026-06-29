from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import os
import secrets as secrets_module
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict

from local_vault.client import (
    api_request,
    delete_server_state,
    is_server_running,
    read_server_state,
)
from local_vault.constants import (
    DEFAULT_HOST,
    SERVER_STATE_FILE,
    VAULT_FILE,
)
from local_vault.crypto import (
    decrypt_vault,
    rewrite_vault_with_new_password,
    write_new_vault,
)
from local_vault.env_parser import (
    normalize_name_affix,
    parse_env_lines,
    read_env_paste_until_end,
    transform_secret_name,
    validate_secret_name,
)
from local_vault.errors import VaultError
from local_vault.storage import atomic_write_json, ensure_vault_home
from local_vault.time_utils import iso_utc, parse_iso_utc, utc_now


def get_free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((DEFAULT_HOST, 0))
        return int(sock.getsockname()[1])


def get_server_command() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "_serve"]

    return [sys.executable, "-m", "local_vault", "_serve"]


def _process_is_running(pid: int) -> bool:
    if pid <= 0:
        return False

    if os.name == "nt":
        completed = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        output = completed.stdout.strip()
        return bool(output) and "No tasks are running" not in output and str(pid) in output

    try:
        os.kill(pid, 0)
    except OSError:
        return False

    return True


def _wait_for_process_exit(pid: int, timeout_seconds: float = 3.0) -> bool:
    deadline = time.time() + timeout_seconds

    while time.time() < deadline:
        if not _process_is_running(pid):
            return True
        time.sleep(0.1)

    return not _process_is_running(pid)


def _force_kill_process(pid: int) -> None:
    if pid <= 0:
        return

    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return

    try:
        os.kill(pid, 9)
    except OSError:
        pass


def _copy_text_to_clipboard(text: str) -> None:
    if os.name == "nt":
        completed = subprocess.run(
            ["clip"],
            input=text,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

        if completed.returncode != 0:
            message = completed.stderr.strip() or "Failed to copy to clipboard."
            raise VaultError(message)

        return

    clipboard_commands = [
        ["pbcopy"],
        ["wl-copy"],
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
    ]

    for command in clipboard_commands:
        try:
            completed = subprocess.run(
                command,
                input=text,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            continue

        if completed.returncode == 0:
            return

    raise VaultError("Could not find a supported clipboard command.")


def _format_env_value(value: str) -> str:
    if value == "":
        return ""

    needs_quotes = (
        value != value.strip()
        or "\n" in value
        or "\r" in value
        or "#" in value
        or '"' in value
        or "'" in value
    )

    if not needs_quotes:
        return value

    return json.dumps(value)


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
        get_server_command(),
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
    server_pid = None

    try:
        state = read_server_state()
        raw_pid = state.get("pid")
        if isinstance(raw_pid, int):
            server_pid = raw_pid
        elif isinstance(raw_pid, str) and raw_pid.isdigit():
            server_pid = int(raw_pid)
    except VaultError:
        pass

    try:
        api_request("/lock", {})
    except VaultError:
        delete_server_state()
        print("Vault is locked.")
        return 0

    if server_pid is not None:
        exited = _wait_for_process_exit(server_pid, timeout_seconds=3.0)

        if not exited:
            _force_kill_process(server_pid)
            _wait_for_process_exit(server_pid, timeout_seconds=2.0)

    delete_server_state()
    print("Vault locked.")
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


def _name_matches_affixes(name: str, prefix: str | None, suffix: str | None) -> bool:
    if prefix is not None and not name.startswith(f"{prefix}_"):
        return False

    if suffix is not None and not name.endswith(f"_{suffix}"):
        return False

    return True


def _strip_affixes(name: str, prefix: str | None, suffix: str | None) -> str:
    env_name = name

    if prefix is not None:
        env_name = env_name[len(prefix) + 1 :]

    if suffix is not None:
        env_name = env_name[: -(len(suffix) + 1)]

    return env_name


def command_export(args: argparse.Namespace) -> int:
    try:
        prefix = normalize_name_affix(args.prefix)
    except VaultError as exc:
        print(f"Invalid prefix: {exc}")
        return 1

    try:
        suffix = normalize_name_affix(args.suffix)
    except VaultError as exc:
        print(f"Invalid suffix: {exc}")
        return 1

    try:
        list_result = api_request("/list", {})
    except VaultError as exc:
        print(str(exc))
        return 1

    all_names = list_result.get("names", [])

    if not isinstance(all_names, list) or not all(isinstance(name, str) for name in all_names):
        print("Vault server returned an invalid secret list.")
        return 1

    selected_names = sorted(
        name for name in all_names if _name_matches_affixes(name, prefix, suffix)
    )

    if not selected_names:
        print("No matching secrets found.")
        if prefix is not None:
            print(f"Prefix filter: {prefix}")
        if suffix is not None:
            print(f"Suffix filter: {suffix}")
        return 1

    print(f"This will copy {len(selected_names)} secret value(s) to your clipboard.")
    print("Save the exported content somewhere else.")
    print("Secret values will not be printed here.")
    print()
    print("Secret names:")

    for name in selected_names:
        print(name)

    print()
    confirmation = input("Type EXPORT to copy these secrets to clipboard: ")

    if confirmation != "EXPORT":
        print("Cancelled.")
        return 1

    try:
        get_result = api_request("/get", {"names": selected_names})
    except VaultError as exc:
        print(str(exc))
        return 1

    secrets = get_result.get("secrets", {})
    missing = get_result.get("missing", [])

    if missing:
        print("Some selected secrets were missing:")
        for name in missing:
            print(name)
        return 1

    if not isinstance(secrets, dict):
        print("Vault server returned an invalid secret payload.")
        return 1

    lines: list[str] = []

    for name in selected_names:
        value = secrets.get(name)

        if not isinstance(value, str):
            print(f"Vault server returned an invalid value for: {name}")
            return 1

        lines.append(f"{name}={_format_env_value(value)}")

    clipboard_text = "\n".join(lines) + "\n"

    try:
        _copy_text_to_clipboard(clipboard_text)
    except VaultError as exc:
        print(str(exc))
        return 1

    print(f"Copied {len(selected_names)} secret value(s) to clipboard.")
    print("Paste the exported content somewhere else now.")
    return 0


def command_run(args: argparse.Namespace) -> int:
    command = list(args.command)

    if command and command[0] == "--":
        command = command[1:]

    if not command:
        print("Missing command to run.")
        print("Example: vault run --suffix DEV -- python app.py")
        return 1

    try:
        prefix = normalize_name_affix(args.prefix)
    except VaultError as exc:
        print(f"Invalid prefix: {exc}")
        return 1

    try:
        suffix = normalize_name_affix(args.suffix)
    except VaultError as exc:
        print(f"Invalid suffix: {exc}")
        return 1

    try:
        list_result = api_request("/list", {})
    except VaultError as exc:
        print(str(exc))
        return 1

    all_names = list_result.get("names", [])

    if not isinstance(all_names, list) or not all(isinstance(name, str) for name in all_names):
        print("Vault server returned an invalid secret list.")
        return 1

    selected_names = sorted(
        name for name in all_names if _name_matches_affixes(name, prefix, suffix)
    )

    if not selected_names:
        print("No matching secrets found.")
        if prefix is not None:
            print(f"Prefix filter: {prefix}")
        if suffix is not None:
            print(f"Suffix filter: {suffix}")
        return 1

    try:
        get_result = api_request("/get", {"names": selected_names})
    except VaultError as exc:
        print(str(exc))
        return 1

    secrets = get_result.get("secrets", {})
    missing = get_result.get("missing", [])

    if missing:
        print("Some selected secrets were missing:")
        for name in missing:
            print(name)
        return 1

    if not isinstance(secrets, dict):
        print("Vault server returned an invalid secret payload.")
        return 1

    env = os.environ.copy()
    mapped_names: Dict[str, str] = {}

    for vault_name in selected_names:
        value = secrets.get(vault_name)

        if not isinstance(value, str):
            print(f"Vault server returned an invalid value for: {vault_name}")
            return 1

        env_name = _strip_affixes(vault_name, prefix, suffix)

        try:
            validate_secret_name(env_name)
        except VaultError as exc:
            print(f"Invalid environment variable name after prefix/suffix stripping: {env_name}")
            print(str(exc))
            return 1

        if env_name in mapped_names:
            print("Two vault secrets map to the same environment variable:")
            print(f"{mapped_names[env_name]} -> {env_name}")
            print(f"{vault_name} -> {env_name}")
            return 1

        mapped_names[env_name] = vault_name
        env[env_name] = value

    try:
        completed = subprocess.run(command, env=env)
    except FileNotFoundError:
        print(f"Command not found: {command[0]}")
        return 127

    return int(completed.returncode)