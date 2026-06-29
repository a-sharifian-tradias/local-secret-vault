# Local Secret Vault

Local Secret Vault is a small local encrypted secrets vault for development workflows.

It lets you store secrets locally, unlock them for a limited time, and run commands with those secrets injected as environment variables.

## Current MVP features

- Encrypted local vault file
- Master password protection
- Timed unlock
- Local in-memory server while unlocked
- Store, list, rename, and delete secrets
- Import `.env` style content
- Run commands with secrets injected into the environment
- Export secrets to clipboard as `.env` text
- Python helper API for loading secrets into Python apps
- Windows executable build

## Recommended Windows setup

Download the release archive and extract it.

After extracting, copy `vault.exe` to a stable folder.

Recommended folder:

```powershell
mkdir $HOME\local-secret-vault
```

```powershell
copy .\vault.exe $HOME\local-secret-vault\vault.exe
```

Then use the app from there:

```powershell
cd $HOME\local-secret-vault
```

```powershell
.\vault.exe --help
```

Do not keep running `vault.exe` directly from Downloads. The app starts a temporary local background process while unlocked, so using a stable folder gives a cleaner Windows experience.

## Initialize a vault

```powershell
.\vault.exe init
```

You will be asked to create a master password.

Important:

If you forget the master password, your secrets cannot be recovered.

## Unlock the vault

```powershell
.\vault.exe unlock --hours 8
```

The vault stays unlocked for the selected number of hours.

While unlocked, secrets are kept in memory by a local background process.

## Check status

```powershell
.\vault.exe status
```

## Add a secret

```powershell
.\vault.exe set API_KEY_DEV
```

The secret value is hidden while typing.

## List secret names

```powershell
.\vault.exe list
```

Only secret names are printed. Secret values are not printed.

## Import `.env` content

```powershell
.\vault.exe import-env --suffix DEV
```

Paste `.env` style content:

```text
API_KEY=example-key
DATABASE_URL=postgres://example
REDIS_URL=redis://localhost:6379
END
```

The final `END` line tells the vault you are done pasting.

With `--suffix DEV`, these become:

```text
API_KEY_DEV
DATABASE_URL_DEV
REDIS_URL_DEV
```

## Import without saving

Use dry-run to preview names before storing anything:

```powershell
.\vault.exe import-env --suffix DEV --dry-run
```

## Overwrite existing secrets during import

```powershell
.\vault.exe import-env --suffix DEV --overwrite
```

## Run an app with secrets loaded

```powershell
.\vault.exe run --suffix DEV -- python app.py
```

This loads matching secrets into the child process environment.

Example mapping:

```text
API_KEY_DEV -> API_KEY
DATABASE_URL_DEV -> DATABASE_URL
REDIS_URL_DEV -> REDIS_URL
```

Inside Python:

```python
import os

api_key = os.environ["API_KEY"]
database_url = os.environ["DATABASE_URL"]
```

Secret values are not printed by the vault.

## Use from Python

You can also use Local Secret Vault from another Python project.

Install the package:

```powershell
pip install localvault
```

Then unlock the vault first:

```powershell
vault unlock --hours 8
```

In your Python app:

```python
from localsecretvault import load_secrets

load_secrets(suffix="DEV")
```

Example mapping:

```text
API_KEY_DEV -> os.environ["API_KEY"]
DATABASE_URL_DEV -> os.environ["DATABASE_URL"]
```

You can also read one secret directly:

```python
from localsecretvault import get_secret

api_key = get_secret("API_KEY_DEV")
```

Or list secret names:

```python
from localsecretvault import list_secret_names

names = list_secret_names(suffix="DEV")
```

The vault must already be unlocked before using these helpers.

## Export secrets to clipboard

To copy all secrets to clipboard as `.env` text:

```powershell
.\vault.exe export
```

To copy only secrets with a suffix:

```powershell
.\vault.exe export --suffix DEV
```

The export command:

- requires the vault to be unlocked
- shows secret names only
- asks you to type `EXPORT`
- copies secret values to clipboard
- does not print secret values in the terminal

Example exported format:

```text
API_KEY_DEV=actual-secret-value
DATABASE_URL_DEV=actual-secret-value
REDIS_URL_DEV=actual-secret-value
```

Save the exported content somewhere else.

## Rename a secret

```powershell
.\vault.exe rename OLD_NAME NEW_NAME
```

To overwrite the target name if it already exists:

```powershell
.\vault.exe rename OLD_NAME NEW_NAME --overwrite
```

## Delete a secret

```powershell
.\vault.exe delete API_KEY_DEV
```

You will be asked to confirm before deletion.

## Change master password

First lock the vault:

```powershell
.\vault.exe lock
```

Then run:

```powershell
.\vault.exe change-password
```

## Lock the vault

```powershell
.\vault.exe lock
```

This stops the local background process and removes the temporary server state.

## Daily usage

Typical daily flow:

```powershell
cd $HOME\local-secret-vault
```

```powershell
.\vault.exe unlock --hours 8
```

```powershell
.\vault.exe run --suffix DEV -- python app.py
```

When finished:

```powershell
.\vault.exe lock
```

## Where data is stored

By default, the encrypted vault is stored under:

```text
C:\Users\<YourUser>\.local-secrets
```

The main encrypted vault file is:

```text
C:\Users\<YourUser>\.local-secrets\vault.json
```

The vault file is encrypted. Do not edit it manually.

## Environment variable

You can override the vault storage location with:

```powershell
$env:LOCAL_SECRET_VAULT_HOME = "C:\path\to\vault-folder"
```

Most users do not need this.

## Security notes

- Secrets are encrypted on disk.
- Secrets are decrypted only while the vault is unlocked.
- While unlocked, secrets are available to the local vault process.
- `vault run` passes selected secrets only to the command you run.
- Python helpers load selected secrets into the current Python process.
- `vault export` copies decrypted secrets to the clipboard.
- Clipboard content may be visible to other apps while it remains in the clipboard.
- Lock the vault when finished.

## Build from source

Install dependencies in a virtual environment, then run:

```powershell
.\build.ps1
```

The built executable will be created at:

```text
dist\vault.exe
```