# Parallel Accounts

Firefox extension for running multiple accounts side by side. Each saved profile gets its own [Firefox container](https://support.mozilla.org/en-US/kb/containers) (contextual identity), so cookies, localStorage, and login sessions stay isolated per profile — no more logging in and out to switch accounts.

## Features

- **Per-profile containers** — every profile opens in its own isolated container tab. Cookies and storage never leak between profiles.
- **Encrypted password vault** — saved passwords are encrypted at rest (PBKDF2 + AES-GCM) behind a master password you choose. The derived key lives only in memory for the session and is never stored.
- **Autofill** — the content script fills saved credentials into the active profile's tab once the vault is unlocked.
- **CSV export/import** — back up or migrate profiles as CSV, gated behind master password verification.
- **Vault reset** — forgot your master password? Reset wipes the vault and saved passwords, but keeps profile names/emails/URLs/containers intact.
- **Profile deletion** — remove a profile (and its container) with a confirmation step.

## Install (development)

Firefox only — the extension uses `contextualIdentities`, a Firefox-only API with no Chrome equivalent.

1. Open `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on**
3. Select [manifest.json](manifest.json)

The temporary install is removed when Firefox closes. For a persistent install, package and sign through AMO (addons.mozilla.org).

## Permissions

| Permission | Why |
|---|---|
| `contextualIdentities` | Create/manage one container per profile |
| `cookies` | Check container-scoped cookie state |
| `tabs` | Open/track each profile's isolated tab |
| `storage` | Persist profiles and the encrypted vault |

## Security notes

- Passwords are encrypted with a key derived from your master password (PBKDF2 → AES-GCM). The key is cached in `storage.session` (memory-only, cleared on browser restart), not written to disk.
- There is no password recovery. Resetting the vault after a forgotten master password permanently deletes saved passwords; profile metadata (name/email/URL/container) is kept.

## Project structure

- [manifest.json](manifest.json) — MV3 manifest, Firefox-targeted
- [background.js](background.js) — profile/container management, vault crypto, message handlers
- [content.js](content.js) — autofill on the page
- [popup.html](popup.html) / [popup.js](popup.js) — UI
- [icons/](icons/) — extension icons

## License

[MIT](LICENSE)
