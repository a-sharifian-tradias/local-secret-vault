import argparse
import sys

from local_vault.commands import (
    command_change_password,
    command_delete,
    command_import_env,
    command_init,
    command_list,
    command_lock,
    command_rename,
    command_set,
    command_status,
    command_unlock,
)
from local_vault.errors import VaultError
from local_vault.server import run_server_from_stdin


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vault", description="Local encrypted secrets vault.")
    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser("init", help="Initialize a new encrypted vault.")
    init_parser.set_defaults(func=command_init)

    change_password_parser = subparsers.add_parser("change-password", help="Change the vault master password.")
    change_password_parser.set_defaults(func=command_change_password)

    unlock_parser = subparsers.add_parser("unlock", help="Unlock vault for a limited time.")
    unlock_parser.add_argument("--hours", type=float, default=8, help="Number of hours to keep vault unlocked.")
    unlock_parser.set_defaults(func=command_unlock)

    lock_parser = subparsers.add_parser("lock", help="Lock the vault immediately.")
    lock_parser.set_defaults(func=command_lock)

    status_parser = subparsers.add_parser("status", help="Show vault status.")
    status_parser.set_defaults(func=command_status)

    list_parser = subparsers.add_parser("list", help="List secret names only.")
    list_parser.set_defaults(func=command_list)

    set_parser = subparsers.add_parser("set", help="Store or update a secret.")
    set_parser.add_argument("name", help="Secret name, for example DATABASE_URL.")
    set_parser.set_defaults(func=command_set)

    delete_parser = subparsers.add_parser("delete", help="Delete a secret from the vault.")
    delete_parser.add_argument("name", help="Secret name to delete, for example OLD_API_KEY.")
    delete_parser.set_defaults(func=command_delete)

    rename_parser = subparsers.add_parser("rename", help="Rename a secret without printing its value.")
    rename_parser.add_argument("old_name", help="Existing secret name.")
    rename_parser.add_argument("new_name", help="New secret name.")
    rename_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite the target secret if it already exists.",
    )
    rename_parser.set_defaults(func=command_rename)

    import_env_parser = subparsers.add_parser("import-env", help="Paste .env content and import it into the vault.")
    import_env_parser.add_argument("--prefix", help="Prefix to add to every imported secret name.")
    import_env_parser.add_argument("--suffix", help="Suffix to add to every imported secret name.")
    import_env_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and show names only. Do not store anything.",
    )
    import_env_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing secrets with imported values.",
    )
    import_env_parser.set_defaults(func=command_import_env)

    return parser


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