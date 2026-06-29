from typing import Dict

from local_vault.errors import VaultError


def validate_secret_name(name: str) -> None:
    if not name:
        raise VaultError("Secret name cannot be empty.")

    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
    if any(char not in allowed for char in name):
        raise VaultError("Secret name may only contain letters, numbers, and underscores.")

    if name[0].isdigit():
        raise VaultError("Secret name must not start with a digit.")


def normalize_name_affix(value: str | None) -> str | None:
    if value is None:
        return None

    normalized = value.strip().strip("_").upper()

    if not normalized:
        return None

    validate_secret_name(normalized)
    return normalized


def transform_secret_name(name: str, prefix: str | None, suffix: str | None) -> str:
    result = name

    normalized_prefix = normalize_name_affix(prefix)
    normalized_suffix = normalize_name_affix(suffix)

    if normalized_prefix:
        result = f"{normalized_prefix}_{result}"

    if normalized_suffix:
        result = f"{result}_{normalized_suffix}"

    validate_secret_name(result)
    return result


def unquote_env_value(value: str) -> str:
    value = value.strip()

    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        inner = value[1:-1]

        if value[0] == '"':
            inner = (
                inner.replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t")
                .replace('\\"', '"')
                .replace("\\\\", "\\")
            )

        return inner

    return value


def parse_env_lines(lines: list[str]) -> Dict[str, str]:
    parsed: Dict[str, str] = {}

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        if line.startswith("export "):
            line = line[len("export ") :].strip()

        if "=" not in line:
            raise VaultError(f"Invalid .env line {line_number}: missing '='")

        name, value = line.split("=", 1)
        name = name.strip()
        value = unquote_env_value(value)

        validate_secret_name(name)

        parsed[name] = value

    return parsed


def read_env_paste_until_end() -> list[str]:
    print("Paste .env content now.")
    print("Finish by typing a line containing only: END")
    print()

    lines = []

    while True:
        try:
            line = input()
        except EOFError:
            break

        if line == "END":
            break

        lines.append(line)

    return lines