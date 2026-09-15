# GDriveStreaming Drive on Demand

> **Status: public self-hosted beta.** The v0.2.2 release distributes only plugin artefacts: it contains no broker, OAuth client, callback host, Google account or Drive data. Physical iOS/Android validation is still pending; use only an operator-owned broker and harmless test data.

GDriveStreaming Drive on Demand is a self-hosted, **read-only** Obsidian mobile plugin for browsing an existing Google Drive knowledge tree. It provides a plugin-owned remote browser, metadata search, and explicit on-demand materialisation of one selected file for iOS and Android. It does not turn remote Drive records into native Obsidian vault files.

## What it does

- Uses an **operator-configured HTTPS broker** only for mobile OAuth pairing and device-bound lease delivery.
- Reads Google Drive metadata and selected file bytes **directly from Google** after a valid lease; the broker never proxies, indexes, or stores Drive file content.
- Enforces Google `drive.readonly` and an operator-configured allowed-root guard.
- Lists metadata before downloading a user-selected file into `_gdrive-stream-cache/by-id/`.
- Refuses cache overwrite and contains no Drive create, upload, rename, move, trash, or delete path.
- Keeps client secrets, refresh tokens, access tokens, authorisation codes, and enrolment codes out of plugin `data.json`.

## Important boundaries

- **Read-only is not folder-scoped OAuth.** Google Drive OAuth scopes cannot be restricted to one folder ID. The selected root is a product guard, not an OAuth permission boundary. Start with a harmless, dedicated test root.
- **Remote-only files are plugin-owned.** Obsidian File Explorer, Search, Quick Switcher, graph, Dataview, Canvas, and native embeds only work while a file is materialised locally.
- **The local cache is sensitive data.** It is removable locally, but materialised content inherits the device and vault security boundary.
- **No broker is preconfigured.** A fresh install has no broker URL and no allowed root; every operator supplies their own infrastructure and Google OAuth client.

## Architecture

```text
Obsidian iOS / Android
  ├─ pairing + callback completion ── HTTPS broker ── Google OAuth
  └─ read-only metadata / selected bytes ─────────── Google Drive API

Broker: no Drive data plane; dedicated service account; encrypted broker state only.
Plugin: no client secret; no refresh-token persistence; plugin-owned cache only.
```

See [ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY.md](SECURITY.md) for the trust boundaries and threat model.

## Self-hosting from source

1. Read [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md) before creating an OAuth client or exposing a route.
2. Create a dedicated harmless Drive test root, for example `example-test-root`.
3. Set `GDRIVE_STREAM_ALLOWED_ROOT_NAME` in the broker runtime configuration and set **Allowed Drive test root** in the plugin settings to the **same** name. The broker refuses to start without an explicit root.
4. Install the versioned system-service and AppArmor templates from `deploy/` as described in the guide.
5. Prove the broker process cannot access either your production Drive mount or the test Drive mount before completing Google consent.
6. Record non-secret results with [docs/DEPLOYMENT_EVIDENCE.md](docs/DEPLOYMENT_EVIDENCE.md), including iOS and Android acceptance.

> The root name is a two-sided contract. The broker seals it into every device lease and the plugin rejects a lease sealed to a different root. Change it in both places together.

## Install the beta with BRAT

1. In Obsidian, install and enable [BRAT](https://github.com/TfTHacker/obsidian42-brat).
2. In BRAT, choose **Add beta plugin** and enter this repository's `owner/repository` identifier.
3. Choose **v0.2.2** and enable **GDriveStreaming Drive on Demand**.
4. Copy the full 64-character lowercase **Device enrollment fingerprint** shown by the plugin; this exact value is what the broker binds to the one-time code.
5. Configure **your own** HTTPS broker URL and the same harmless test-root name on broker and plugin before enrolling a device.

This release does not grant access to any shared Google account or service. A Google OAuth client in testing mode must be restricted to the operator's intended test users. Do not connect production data; see [STATUS.md](STATUS.md), [SECURITY_DECISION.md](SECURITY_DECISION.md), and [MOBILE_BETA_ACCEPTANCE.md](MOBILE_BETA_ACCEPTANCE.md).

## Development and verification

```bash
npm ci
npm run verify
```

`npm run verify` runs TypeScript checking, tests, the plugin build, and the broker build. CI also confirms the committed `main.js` is reproducible from source and publishes checksums for release artefacts.

## Documentation

- [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md) — generic self-hosting, isolation, OAuth, and recovery procedure.
- [docs/DEPLOYMENT_EVIDENCE.md](docs/DEPLOYMENT_EVIDENCE.md) — non-secret evidence template.
- [ARCHITECTURE.md](ARCHITECTURE.md) — data flow and Obsidian API limits.
- [SECURITY.md](SECURITY.md) and [PRIVACY.md](PRIVACY.md) — security, privacy, and reporting policy.
- [TESTING.md](TESTING.md) and [MOBILE_BETA_ACCEPTANCE.md](MOBILE_BETA_ACCEPTANCE.md) — automated and physical-device acceptance scope.
- [FORK_PROVENANCE.md](FORK_PROVENANCE.md), [UPSTREAM_AUDIT.md](UPSTREAM_AUDIT.md), and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) — upstream provenance and licence notices.

## Provenance and credit

This project is an independently maintained derivative of [solutions-real-it-org/obsidian-drive-on-demand](https://github.com/solutions-real-it-org/obsidian-drive-on-demand), audited at commit [`25f7149789d53672af4b04722d7fedc435cc47ce`](https://github.com/solutions-real-it-org/obsidian-drive-on-demand/commit/25f7149789d53672af4b04722d7fedc435cc47ce).

The upstream project is MIT-licensed by Real-IT / Loïc Bertrand. The required licence and attribution are preserved in [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). This project is **not endorsed by Real-IT or Obsidian**.
