from __future__ import annotations

import os
from typing import Dict

from local_vault.client import api_request
from local_vault.env_parser import normalize_name_affix, validate_secret_name
from local_vault.errors import VaultError


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


def list_secret_names(
    *,
    prefix: str | None = None,
    suffix: str | None = None,
) -> list[str]:
    """
    Return secret names from the currently unlocked vault.

    The vault must already be unlocked with the CLI:

        vault unlock --hours 8
    """
    prefix = normalize_name_affix(prefix)
    suffix = normalize_name_affix(suffix)

    result = api_request("/list", {})
    names = result.get("names", [])

    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise VaultError("Vault server returned an invalid secret list.")

    return sorted(name for name in names if _name_matches_affixes(name, prefix, suffix))


def get_secret(name: str) -> str:
    """
    Return one secret value from the currently unlocked vault.

    Secret values are not printed.
    """
    validate_secret_name(name)

    result = api_request("/get", {"names": [name]})
    secrets = result.get("secrets", {})
    missing = result.get("missing", [])

    if missing:
        raise VaultError(f"Secret not found: {name}")

    if not isinstance(secrets, dict):
        raise VaultError("Vault server returned an invalid secret payload.")

    value = secrets.get(name)

    if not isinstance(value, str):
        raise VaultError(f"Vault server returned an invalid value for: {name}")

    return value


def load_secrets(
    *,
    prefix: str | None = None,
    suffix: str | None = None,
    strip: bool = True,
    override: bool = True,
) -> Dict[str, str]:
    """
    Load matching vault secrets into os.environ and return the loaded mapping.

    The vault must already be unlocked with the CLI:

        vault unlock --hours 8

    Example:

        from localsecretvault import load_secrets

        load_secrets(suffix="DEV")

    With suffix="DEV" and strip=True:

        API_KEY_DEV -> os.environ["API_KEY"]
        DATABASE_URL_DEV -> os.environ["DATABASE_URL"]

    Args:
        prefix: Only load secrets with this prefix.
        suffix: Only load secrets with this suffix.
        strip: Remove the prefix/suffix from environment variable names.
        override: Replace existing os.environ values if they already exist.

    Returns:
        A dictionary of environment variable names and loaded values.
    """
    prefix = normalize_name_affix(prefix)
    suffix = normalize_name_affix(suffix)

    selected_names = list_secret_names(prefix=prefix, suffix=suffix)

    if not selected_names:
        return {}

    result = api_request("/get", {"names": selected_names})
    secrets = result.get("secrets", {})
    missing = result.get("missing", [])

    if missing:
        missing_names = ", ".join(str(name) for name in missing)
        raise VaultError(f"Some selected secrets were missing: {missing_names}")

    if not isinstance(secrets, dict):
        raise VaultError("Vault server returned an invalid secret payload.")

    loaded: Dict[str, str] = {}

    for vault_name in selected_names:
        value = secrets.get(vault_name)

        if not isinstance(value, str):
            raise VaultError(f"Vault server returned an invalid value for: {vault_name}")

        if strip:
            env_name = _strip_affixes(vault_name, prefix, suffix)
        else:
            env_name = vault_name

        validate_secret_name(env_name)

        if env_name in loaded:
            raise VaultError(f"Two vault secrets map to the same environment variable: {env_name}")

        loaded[env_name] = value

    for env_name, value in loaded.items():
        if override or env_name not in os.environ:
            os.environ[env_name] = value

    return loaded