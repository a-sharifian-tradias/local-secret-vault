import base64
import json
import os
from typing import Any, Dict, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from local_vault.constants import KDF_ITERATIONS, KDF_NAME, VAULT_FILE, VAULT_VERSION
from local_vault.errors import VaultError
from local_vault.storage import atomic_write_json, ensure_vault_home, read_json
from local_vault.time_utils import iso_utc, utc_now


def derive_fernet_key(master_password: str, salt: bytes, iterations: int) -> bytes:
    password_bytes = master_password.encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )

    raw_key = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(raw_key)


def encrypt_secrets_dict(secrets_dict: Dict[str, str], fernet_key: bytes) -> str:
    payload = {
        "secrets": secrets_dict,
        "updated_at": iso_utc(utc_now()),
    }
    plaintext = json.dumps(payload, sort_keys=True).encode("utf-8")
    token = Fernet(fernet_key).encrypt(plaintext)
    return token.decode("utf-8")


def decrypt_vault(master_password: str) -> Tuple[Dict[str, str], bytes]:
    if not VAULT_FILE.exists():
        raise VaultError(
            f"Vault does not exist yet: {VAULT_FILE}\n"
            "Run: vault init"
        )

    vault_data = read_json(VAULT_FILE)

    if vault_data.get("version") != VAULT_VERSION:
        raise VaultError(f"Unsupported vault version: {vault_data.get('version')}")

    if vault_data.get("kdf") != KDF_NAME:
        raise VaultError(f"Unsupported KDF: {vault_data.get('kdf')}")

    iterations = int(vault_data["iterations"])
    salt = base64.b64decode(vault_data["salt_b64"])
    token = vault_data["fernet_token"].encode("utf-8")

    fernet_key = derive_fernet_key(master_password, salt, iterations)

    try:
        plaintext = Fernet(fernet_key).decrypt(token)
    except InvalidToken as exc:
        raise VaultError(
            "Could not unlock vault. The master password may be wrong, or the vault file may be corrupted."
        ) from exc

    payload = json.loads(plaintext.decode("utf-8"))
    secrets_dict = payload.get("secrets", {})

    if not isinstance(secrets_dict, dict):
        raise VaultError("Vault payload is invalid: expected a dictionary of secrets.")

    clean_secrets = {}
    for key, value in secrets_dict.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise VaultError("Vault payload is invalid: secret names and values must be strings.")
        clean_secrets[key] = value

    return clean_secrets, fernet_key


def write_vault_with_key(
    secrets_dict: Dict[str, str],
    fernet_key: bytes,
    existing_vault_data: Dict[str, Any],
) -> None:
    encrypted_token = encrypt_secrets_dict(secrets_dict, fernet_key)

    new_vault_data = {
        "version": VAULT_VERSION,
        "kdf": existing_vault_data["kdf"],
        "iterations": existing_vault_data["iterations"],
        "salt_b64": existing_vault_data["salt_b64"],
        "fernet_token": encrypted_token,
    }

    atomic_write_json(VAULT_FILE, new_vault_data)


def write_new_vault(master_password: str) -> None:
    ensure_vault_home()

    if VAULT_FILE.exists():
        raise VaultError(f"Vault already exists: {VAULT_FILE}")

    salt = os.urandom(16)
    fernet_key = derive_fernet_key(master_password, salt, KDF_ITERATIONS)

    vault_data = {
        "version": VAULT_VERSION,
        "kdf": KDF_NAME,
        "iterations": KDF_ITERATIONS,
        "salt_b64": base64.b64encode(salt).decode("utf-8"),
        "fernet_token": encrypt_secrets_dict({}, fernet_key),
    }

    atomic_write_json(VAULT_FILE, vault_data)


def rewrite_vault_with_new_password(secrets_dict: Dict[str, str], new_master_password: str) -> None:
    salt = os.urandom(16)
    fernet_key = derive_fernet_key(new_master_password, salt, KDF_ITERATIONS)

    vault_data = {
        "version": VAULT_VERSION,
        "kdf": KDF_NAME,
        "iterations": KDF_ITERATIONS,
        "salt_b64": base64.b64encode(salt).decode("utf-8"),
        "fernet_token": encrypt_secrets_dict(secrets_dict, fernet_key),
    }

    atomic_write_json(VAULT_FILE, vault_data)