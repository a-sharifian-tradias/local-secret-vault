import sys

from local_vault.cli import build_parser
from local_vault.errors import VaultError
from local_vault.server import run_server_from_stdin


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