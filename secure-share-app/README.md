# VaultDrop Secure Share

A local-first secure file-sharing demo with client-side encryption.

## What it does

- Encrypts files in the browser using AES-GCM
- Derives keys from a passphrase with PBKDF2
- Uploads only ciphertext to the Python server
- Supports expiry windows and maximum download counts
- Decrypts files in the recipient browser after they enter the passphrase

## Run

```powershell
cd "C:\Users\hello\OneDrive\Documents\New project\secure-share-app"
python server.py
```

Then open `http://127.0.0.1:8000`.

## Notes

- This is a portfolio/demo app, not a production-hardened service.
- Share the link and passphrase through separate channels.
- For a production version, add authenticated uploads, virus scanning, audit logs, rate limiting, and stronger secret-handling controls.
