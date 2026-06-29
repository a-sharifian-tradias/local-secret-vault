\# Roadmap



\## Current phase



Finish the core local encrypted vault and make the developer workflow comfortable.



\## Near-term tasks



\- Add helper function for suffix-based loading, for example loading `API\_KEY\_DEV` into `API\_KEY`.

\- Add tests for `.env` parsing and import behavior.

\- Update daily usage documentation after helper API is finalized.

\- Add a safe way to inspect or export secrets for backup.



\## Later packaging goal



Create an easy-to-run Windows executable.



The final user experience should be simple:



1\. Download or copy the executable.

2\. Run `vault init`.

3\. Run `vault unlock`.

4\. Run `vault set NAME` or `vault import-env`.

5\. Use `local\_vault\_helper.py` from Python projects.

6\. Optionally create a backup snapshot.



\## Snapshot/export goal



Add a command such as:



```powershell

vault snapshot
```

Desired behavior:



Ask for the master password again, even if the vault is currently unlocked.

Decrypt the full vault.

Copy a plaintext backup snapshot to the clipboard.

Print a strong warning that the clipboard now contains plaintext secrets.

Make the format easy to paste into Bitwarden or another password manager.



Possible future safety options:



vault snapshot --format env

vault snapshot --format json

vault snapshot --file backup.json



For the first version, prefer clipboard-only if it keeps the workflow simple.

