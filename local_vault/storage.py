import json
from pathlib import Path
from typing import Any, Dict

from local_vault.constants import VAULT_HOME
from local_vault.errors import VaultError


def ensure_vault_home() -> None:
    VAULT_HOME.mkdir(parents=True, exist_ok=True)


def atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    ensure_vault_home()
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp_path.replace(path)


def read_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise VaultError(f"File not found: {path}")
    except json.JSONDecodeError as exc:
        raise VaultError(f"Invalid JSON in {path}: {exc}") from exc