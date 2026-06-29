# Local Secret Vault - Maintenance and Security Notes

## Files

Vault project:

C:\Users\AriaSharifian\PycharmProjects\local-secret-vault

Encrypted vault file:

C:\Users\AriaSharifian\.local-secrets\vault.json

Temporary server state file:

C:\Users\AriaSharifian\.local-secrets\server.json

## What is safe to commit

These files are okay to commit:

vault.py
local_vault_helper.py
requirements.txt
.gitignore
DAILY_USAGE.md
project-gitignore-template.txt
MAINTENANCE.md

## What must not be committed

Never commit:

C:\Users\AriaSharifian\.local-secrets\
vault.json
server.json
.env
.env.*
*.env
.venv/

## Back up encrypted vault

Back up only:

C:\Users\AriaSharifian\.local-secrets\vault.json

Example:

$backupDir = "C:\Users\AriaSharifian\Documents\vault-backups"
New-Item -ItemType Directory -Force $backupDir

Copy-Item `
  "C:\Users\AriaSharifian\.local-secrets\vault.json" `
  "$backupDir\vault-$(Get-Date -Format yyyyMMdd-HHmmss).json"

## Restore encrypted vault

Copy a backup back to:

C:\Users\AriaSharifian\.local-secrets\vault.json

Then unlock:

vault unlock --hours 8

## Rotate a secret

vault unlock --hours 8
vault set SECRET_NAME

Then restart any Python process or Jupyter kernel that already loaded the old value.

## Security model

This protects against someone reading your disk while the vault is locked.

This helps with:

- stolen laptop risk
- accidental plaintext .env files
- accidental Git commits of plaintext secrets
- avoiding global Windows environment variables

This does not fully protect against:

- malware running as your Windows user
- a malicious process running while the vault is unlocked
- a compromised IDE plugin
- code that prints secrets
- notebook outputs containing secrets
- memory inspection of the unlocked server process

## Recovery limitation

If you forget the master password, secrets cannot be recovered.

Backups of vault.json are only useful if you still know the master password.

## Best practices

Use a strong unique master password.
Unlock only for as long as needed.
Run vault lock when done.
Do not print secrets.
Do not log secrets.
Do not commit notebook outputs containing secrets.
Rotate any secret that was ever stored in a plaintext .env file committed to Git.
