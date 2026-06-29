\# Local Secret Vault



Local Secret Vault is a local encrypted secrets manager for development workflows.



It stores secrets encrypted on disk and unlocks them into a local in-memory server for a limited time. Secrets can then be injected into child processes as environment variables.



\## MVP workflow



Build the Windows executable:



```powershell

.\\build.ps1

```



Unlock the vault:



```powershell

.\\dist\\vault.exe unlock --hours 8

```



Import `.env` content with a suffix:



```powershell

.\\dist\\vault.exe import-env --suffix DEV

```



Paste `.env` content, then finish with:



```text

END

```



Example imported names:



```text

API\_KEY\_DEV

DATABASE\_URL\_DEV

REDIS\_URL\_DEV

```



Run an app with suffix-based environment loading:



```powershell

.\\dist\\vault.exe run --suffix DEV -- python app.py

```



This injects:



```text

API\_KEY\_DEV -> API\_KEY

DATABASE\_URL\_DEV -> DATABASE\_URL

REDIS\_URL\_DEV -> REDIS\_URL

```



The app reads normal environment variables:



```python

import os



api\_key = os.environ\["API\_KEY"]

database\_url = os.environ\["DATABASE\_URL"]

```



\## Common commands



```powershell

.\\dist\\vault.exe status

```



```powershell

.\\dist\\vault.exe list

```



```powershell

.\\dist\\vault.exe set API\_KEY\_DEV

```



```powershell

.\\dist\\vault.exe delete API\_KEY\_DEV

```



```powershell

.\\dist\\vault.exe rename OLD\_NAME\_DEV NEW\_NAME\_DEV

```



```powershell

.\\dist\\vault.exe lock

```



\## Source-mode development



From the project root:



```powershell

.\\.venv\\Scripts\\Activate.ps1

```



```powershell

vault status

```



```powershell

vault run --suffix DEV -- .\\.venv\\Scripts\\python.exe app.py

```



\## Safety notes



Secrets are encrypted on disk.



When unlocked, decrypted secrets live in memory inside a local server until the unlock window expires or you run:



```powershell

.\\dist\\vault.exe lock

```



Do not commit vault files, `.env` files, or build artifacts.

