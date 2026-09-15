# Mobile beta acceptance — operator-configured harmless test root

## Scope lock

- **Supported runtime under test:** Android and iPhone/iPad only.
- **Desktop:** remains on the existing file-server workflow; this plugin does not replace it.
- **Only permitted Drive root:** the single harmless test root the operator names in **both** the broker (`GDRIVE_STREAM_ALLOWED_ROOT_NAME`) and the plugin settings (**Allowed Drive test root**). `example-test-root` is a documentation example, not a fixed rule; the broker has no default root and refuses to start without an explicit value.
- **Forbidden root:** any production knowledge tree and every folder below it.
- **Beta permissions:** read/list/download only. No upload, move, rename, trash or delete.

## Pre-flight

- [ ] Plugin version, broker version and tested commit recorded.
- [ ] Broker API URL is HTTPS, operator-controlled, reachable only over the operator's private route, and exposes only the pairing API.
- [ ] Public Google callback is a separately exposed, narrow callback route configured by the operator; it is not the mobile broker base URL.
- [ ] Google consent screen identifies the operator-controlled project.
- [ ] Broker logs are redacted; no Google credential or file content appears in them.
- [ ] Test fixture contains only harmless Markdown, PDF and image content.

## Android and iOS test matrix

Run each scenario independently on a physical Android device and physical iPhone/iPad:

- [ ] Launch plugin; no cached token means Connect flow is visible.
- [ ] OAuth pairing succeeds once; replaying the claimed pairing fails.
- [ ] Cancelling OAuth leaves no usable session.
- [ ] Metadata tree loads only from the configured test root and contains no file bytes before an item opens.
- [ ] Markdown, PDF and image download/open on demand.
- [ ] An interrupted download/restart does not corrupt or overwrite a cache item.
- [ ] Airplane mode reports an error without remote mutation.
- [ ] Network recovery supports a new metadata refresh.
- [ ] Inspect plugin `data.json`: it has no `deviceIdentity` section and contains neither serialized private-key string.
- [ ] Logout clears the Obsidian SecretStorage device identity and local pair id, then a new browse/refresh attempt is blocked before any Drive request until re-enrollment.
- [ ] For a lost phone, record operator remote revocation through the broker admin path; logout is local only and does not revoke remotely.
- [ ] Inspect captured network/log evidence: mobile pairing reaches only the operator's private pairing route; browser consent returns only through the separately exposed callback route; no upstream endpoint appears.
- [ ] Attempted Drive write/move/rename/trash/delete is absent from UI and transport evidence.

## Implemented read-only flow (v0.2 branch)

- The browser view shows an explicit **Not enrolled** state (with the device fingerprint) and an **Enrol this device** action until pairing succeeds; no Drive request is attempted in that state.
- Enrollment runs through the lease manager: pair with the one-time code, open the authorization URL, poll until consent completes. The code is transient and is never persisted.
- Browsing is confined to the operator-configured root; any path or id outside it is refused in the UI layer before a request is issued. The plugin refuses a lease sealed to any other root, so a broker/plugin mismatch pairs but never yields a usable lease.
- Search and listing are metadata-only; content leaves Drive only through an explicit, size-capped single-file download. There is no create/rename/move/delete/trash affordance and no full-vault sync.
- Lease renewal survives a plugin restart (persisted pair id + fresh nonce/lease) and falls back to **re-enrol required** on a 410 pairing expiry or a 403 revocation.
- `data.json` persists only broker base URL, the configured allowed root name, pair id and enrollment status/metadata; it contains no device private keys. Ed25519/X25519 private identity is stored separately through Obsidian SecretStorage, which Obsidian documents as local, per-vault storage.
- This beta does **not** claim iOS Keychain or Android Keystore protection. A malicious same-vault plugin or a compromised unlocked device remains a risk.
- Logout clears the local SecretStorage identity, pair id, lease and token state, so a new request is blocked until re-enrollment. It does not revoke the remote enrollment; an operator must do that for a lost phone.

## Abort criteria

Stop and do not connect production data if any item reaches a production knowledge tree, a token enters plugin data/logs, an upstream endpoint is contacted, a cache overwrite/deletion occurs, pairing can be replayed, or any remote mutation is attempted.

## Evidence record

For each device record: device/OS, plugin commit, broker revision, test date, pass/fail per case, redacted error identifiers, and reviewer. Never attach tokens, cookie headers, OAuth codes or personal note contents.
