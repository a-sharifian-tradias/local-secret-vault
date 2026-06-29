import json
import os
from pathlib import Path
from typing import Iterable, Mapping
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError


class LocalVaultError(RuntimeError):
    pass


class LocalVaultLockedError(LocalVaultError):
    pass


class LocalVaultMissingSecretError(LocalVaultError):
    pass


def _vault_home() -> Path:
    return Path(os.environ.get("LOCAL_SECRET_VAULT_HOME", str(Path.home() / ".local-secrets")))


def _server_state_file() -> Path:
    return _vault_home() / "server.json"


def _read_server_state() -> dict:
    path = _server_state_file()

    if not path.exists():
        raise LocalVaultLockedError("Vault is locked. Run: vault unlock --hours 8")

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise LocalVaultLockedError("Vault server state is invalid. Run: vault lock, then vault unlock --hours 8") from exc


def _post_json(path: str, payload: dict, timeout_seconds: float = 3.0) -> dict:
    state = _read_server_state()

    host = state["host"]
    port = int(state["port"])
    token = state["token"]

    url = f"http://{host}:{port}{path}"

    body = json.dumps(payload).encode("utf-8")

    req = urllib_request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib_request.urlopen(req, timeout=timeout_seconds) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except HTTPError as exc:
        try:
            error_payload = json.loads(exc.read().decode("utf-8", errors="replace"))
            message = error_payload.get("error", "Vault request failed.")
        except Exception:
            message = "Vault request failed."

        if exc.code in {401, 423}:
            raise LocalVaultLockedError("Vault is locked. Run: vault unlock --hours 8") from exc

        raise LocalVaultError(message) from exc
    except URLError as exc:
        raise LocalVaultLockedError("Vault is locked or unavailable. Run: vault unlock --hours 8") from exc
    except TimeoutError as exc:
        raise LocalVaultError("Vault request timed out.") from exc


def _normalize_secret_request(names: Iterable[str] | Mapping[str, str]) -> dict[str, str]:
    if isinstance(names, Mapping):
        mapping = dict(names)

        if not mapping:
            return {}

        for vault_name, env_name in mapping.items():
            if not isinstance(vault_name, str) or not vault_name:
                raise ValueError("Vault secret names must be non-empty strings.")
            if not isinstance(env_name, str) or not env_name:
                raise ValueError("Environment variable names must be non-empty strings.")

        return mapping

    requested_names = list(names)

    mapping = {}

    for name in requested_names:
        if not isinstance(name, str) or not name:
            raise ValueError("Secret names must be non-empty strings.")
        mapping[name] = name

    return mapping


def load_secrets(names: Iterable[str] | Mapping[str, str], *, override: bool = True) -> None:
    """
    Load secrets from the unlocked local vault into os.environ.

    Supported forms:

        load_secrets(["API_KEY", "DATABASE_URL"])

    This reads API_KEY from the vault and sets os.environ["API_KEY"].

        load_secrets({
            "API_KEY_DEV": "API_KEY",
            "DATABASE_URL_DEV": "DATABASE_URL",
        })

    This reads API_KEY_DEV from the vault and sets os.environ["API_KEY"].
    """

    mapping = _normalize_secret_request(names)

    if not mapping:
        return

    vault_names = list(mapping.keys())

    result = _post_json("/get", {"names": vault_names})

    secrets = result.get("secrets", {})
    missing = result.get("missing", [])

    if missing:
        missing_display = ", ".join(missing)
        raise LocalVaultMissingSecretError(
            f"Missing required secret(s): {missing_display}. "
            f"Add them with: vault set SECRET_NAME"
        )

    for vault_name, env_name in mapping.items():
        if vault_name not in secrets:
            raise LocalVaultMissingSecretError(
                f"Vault response did not include required secret: {vault_name}"
            )

        if override or env_name not in os.environ:
            os.environ[env_name] = secrets[vault_name]


def load_secret(vault_name: str, *, as_env: str | None = None, override: bool = True) -> None:
    """
    Load one secret from the unlocked local vault into os.environ.

    Examples:

        load_secret("API_KEY")

    Reads API_KEY and sets os.environ["API_KEY"].

        load_secret("API_KEY_DEV", as_env="API_KEY")

    Reads API_KEY_DEV and sets os.environ["API_KEY"].
    """

    if not isinstance(vault_name, str) or not vault_name:
        raise ValueError("vault_name must be a non-empty string.")

    env_name = as_env if as_env is not None else vault_name

    if not isinstance(env_name, str) or not env_name:
        raise ValueError("as_env must be a non-empty string.")

    load_secrets({vault_name: env_name}, override=override)