from __future__ import annotations

import argparse

from local_vault.commands import (
    command_change_password,
    command_delete,
    command_export,
    command_import_env,
    command_init,
    command_list,
    command_lock,
    command_rename,
    command_run,
    command_set,
    command_status,
    command_unlock,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault",
        description="Local encrypted secrets vault.",
    )

    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser(
        "init",
        help="Initialize a new encrypted vault.",
    )
    init_parser.set_defaults(func=command_init)

    change_password_parser = subparsers.add_parser(
        "change-password",
        help="Change the vault master password.",
    )
    change_password_parser.set_defaults(func=command_change_password)

    unlock_parser = subparsers.add_parser(
        "unlock",
        help="Unlock vault for a limited time.",
    )
    unlock_parser.add_argument(
        "--hours",
        type=float,
        default=8,
        help="How many hours the vault should stay unlocked.",
    )
    unlock_parser.set_defaults(func=command_unlock)

    lock_parser = subparsers.add_parser(
        "lock",
        help="Lock the vault immediately.",
    )
    lock_parser.set_defaults(func=command_lock)

    status_parser = subparsers.add_parser(
        "status",
        help="Show vault status.",
    )
    status_parser.set_defaults(func=command_status)

    list_parser = subparsers.add_parser(
        "list",
        help="List secret names only.",
    )
    list_parser.set_defaults(func=command_list)

    set_parser = subparsers.add_parser(
        "set",
        help="Store or update a secret.",
    )
    set_parser.add_argument("name", help="Secret name.")
    set_parser.set_defaults(func=command_set)

    delete_parser = subparsers.add_parser(
        "delete",
        help="Delete a secret from the vault.",
    )
    delete_parser.add_argument("name", help="Secret name.")
    delete_parser.set_defaults(func=command_delete)

    rename_parser = subparsers.add_parser(
        "rename",
        help="Rename a secret without printing its value.",
    )
    rename_parser.add_argument("old_name", help="Existing secret name.")
    rename_parser.add_argument("new_name", help="New secret name.")
    rename_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite the new name if it already exists.",
    )
    rename_parser.set_defaults(func=command_rename)

    import_env_parser = subparsers.add_parser(
        "import-env",
        help="Paste .env content and import it into the vault.",
    )
    import_env_parser.add_argument(
        "--prefix",
        default=None,
        help="Prefix to add to every imported secret name.",
    )
    import_env_parser.add_argument(
        "--suffix",
        default=None,
        help="Suffix to add to every imported secret name.",
    )
    import_env_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing secrets.",
    )
    import_env_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be imported without storing anything.",
    )
    import_env_parser.set_defaults(func=command_import_env)

    export_parser = subparsers.add_parser(
        "export",
        help="Copy decrypted secrets to clipboard as .env text.",
    )
    export_parser.add_argument(
        "--prefix",
        default=None,
        help="Only export secrets with this prefix.",
    )
    export_parser.add_argument(
        "--suffix",
        default=None,
        help="Only export secrets with this suffix.",
    )
    export_parser.set_defaults(func=command_export)

    run_parser = subparsers.add_parser(
        "run",
        help="Run a command with vault secrets in its environment.",
    )
    run_parser.add_argument(
        "--prefix",
        default=None,
        help="Only load secrets with this prefix, then strip it from environment names.",
    )
    run_parser.add_argument(
        "--suffix",
        default=None,
        help="Only load secrets with this suffix, then strip it from environment names.",
    )
    run_parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command to run. Use -- before the command.",
    )
    run_parser.set_defaults(func=command_run)

    return parser