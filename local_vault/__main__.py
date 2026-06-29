from __future__ import annotations

import sys

from local_vault.cli import build_parser
from local_vault.errors import VaultError
from local_vault.server import run_server_from_stdin


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "_serve":
        return run_server_from_stdin()

    parser = build_parser()
    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        return 0

    try:
        return int(args.func(args))
    except VaultError as exc:
        print(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())