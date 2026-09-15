# Upstream Audit

Audited upstream repository: `solutions-real-it-org/obsidian-drive-on-demand`, commit `25f7149789d53672af4b04722d7fedc435cc47ce`.

## Licence

Upstream is MIT, copyright `2026 Real-IT (Loïc Bertrand)` (`LICENSE:1-13`). This project retains the required upstream notice in `THIRD_PARTY_NOTICES.md`. No upstream code is assumed safe simply because it is open source.

## Dependency findings

The upstream client is not operationally independent. `src/main.ts:34-39` hard-codes `https://obsidian-drive-on-demand.solutions.real-it.org`, a Real-IT Google client ID, `/callback`, and `/callback-byo`. Managed OAuth opens Google authorization with the Real-IT callback (`src/main.ts:319-324`), retrieves a refresh token from `GET /claim?pairing=` (`src/main.ts:304-309`), and sends refresh tokens to `POST /refresh` (`src/auth/drive-auth.ts:45-60`). The advertised BYO path still uses the Real-IT callback URL.

The broker server/deployment is absent from the repository, so its TLS, token retention, logging and access controls cannot be audited. This alone disqualifies upstream unchanged for the requested ownership model.

## OAuth/security findings

Upstream authorization state is random and validated, but PKCE is absent: `src/auth/state.ts:8-12`, `src/auth/oauth-url.ts:10-21`, `src/auth/google-oauth.ts:34-46`. BYO client secret and refresh token are persisted through reversible Base64 in Obsidian data (`src/auth/token-store.ts:6-29`, `src/auth/byo-store.ts:4-32`), not encrypted secret storage.

Upstream uses broad Drive scope `https://www.googleapis.com/auth/drive` (`src/main.ts:36`). It calls Google Drive v3 list, Changes, download, metadata, create, move/rename and upload endpoints through `requestUrl` (`src/drive/drive-client.ts`).

## Telemetry, updates and subscriptions

Static audit found no client telemetry, analytics, crash-reporting SDK, remote config or in-code auto-updater. Local console diagnostics exist. There is no Stripe/billing/entitlement API in code. However, `PRIVACY.md:31-44` says the unauditable broker has operational logs. Manifest/package/docs include Real-IT author, funding, policy and BRAT URLs.

## Build/dependency findings

Upstream build/tests passed in audit (245 tests), but tests mock HTTP and do not exercise Google/broker. `npm audit` found development-tooling vulnerabilities. `.gitignore` excludes `main.js`, causing `npm pack --dry-run` to omit the plugin entry artifact.

## Replacement decisions

This project uses a new plugin identity `obsidian-gdrive-streaming`, no Real-IT host/client/callback/protocol, no upstream refresh endpoint, no Base64 token storage, no upstream automatic update route, and no auto-merge policy. No upstream Git remote is configured in this public checkout: the audited upstream snapshot is referenced only for manual, explicit review. Any future imported upstream code requires a new audit and preservation of MIT notice.
