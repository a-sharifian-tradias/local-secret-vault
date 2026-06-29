import os
from pathlib import Path

VAULT_HOME = Path(os.environ.get("LOCAL_SECRET_VAULT_HOME", str(Path.home() / ".local-secrets")))
VAULT_FILE = VAULT_HOME / "vault.json"
SERVER_STATE_FILE = VAULT_HOME / "server.json"

VAULT_VERSION = 1
KDF_NAME = "PBKDF2HMAC-SHA256"
KDF_ITERATIONS = 600_000

DEFAULT_HOST = "127.0.0.1"
