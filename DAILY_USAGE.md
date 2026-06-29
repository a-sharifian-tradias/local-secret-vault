# Local Secret Vault - Daily Usage Guide

## Unlock vault in the morning

vault unlock --hours 8

You will be asked for your master password.

## Check status

vault status

## List secret names

vault list

This only prints secret names, not secret values.

## Add or update a secret

vault set SECRET_NAME

Example:

vault set API_KEY

The value is typed securely and is not printed.

## Lock vault manually

vault lock

## Use in a Python project

Copy this file into your project:

C:\Users\AriaSharifian\PycharmProjects\local-secret-vault\local_vault_helper.py

Then in Python:

from local_vault_helper import load_secrets

load_secrets([
    "DATABASE_URL",
    "API_KEY",
    "TEST_VAR",
])

import os

api_key = os.getenv("API_KEY")

## Use in a Jupyter notebook

First cell:

from pathlib import Path
import sys

PROJECT_ROOT = Path.cwd()

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from local_vault_helper import load_secrets

load_secrets([
    "DATABASE_URL",
    "API_KEY",
    "TEST_VAR",
])

If the kernel restarts, rerun the first setup cell.

## Important safety notes

Do not print secrets.
Do not commit .env files.
Do not commit vault.json or server.json.
If you forget the master password, secrets cannot be recovered.
