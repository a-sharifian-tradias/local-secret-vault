from __future__ import annotations

from local_vault.api import get_secret, list_secret_names, load_secrets

__all__ = [
    "get_secret",
    "list_secret_names",
    "load_secrets",
]

__version__ = "0.4.0"