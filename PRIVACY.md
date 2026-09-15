# Privacy disclosure

## Network destinations

When configured and enrolled, the plugin can contact:

- **Your configured HTTPS broker** — one-time enrollment, pairing status and short-lived encrypted lease renewal. It must not receive Drive file content.
- **Google OAuth endpoints** — browser-based consent and token exchange performed by the broker.
- **Google Drive API** — direct read-only metadata requests and the bytes of a file selected by the user.

There is no telemetry, analytics, crash reporter, advertising, remote configuration channel or auto-updater in the plugin.

## Local data

Plugin `data.json` may contain the configured broker URL, pair identifier, enrollment metadata and legacy metadata/cache references. The device identity is stored via Obsidian SecretStorage. Access tokens, refresh tokens, client secrets, authorization codes, enrollment codes and unsealed leases must not be persisted in `data.json`.

Selected downloads are materialized in `_gdrive-stream-cache/by-id/` under the local vault. They can contain sensitive content and remain subject to device and vault protection. Removing this local cache does not modify Google Drive.

## Broker operator data

A self-hosted broker stores only its encrypted authentication/enrollment state and protected configuration. Operators should log only timestamps, route/action category, status code and anonymized error category. They must never log file content, OAuth state/code, bearer credentials, refresh tokens or authorization headers.

## Retention and deletion

The plugin has no central service operated by this project. Retention is controlled by the self-hosting operator, the local Obsidian vault/device and Google Drive. Device logout removes local enrollment and identity material; an operator must revoke a lost device through the broker administration path.
