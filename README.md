# GDrive Streaming

> **Status: public self-hosted beta.** The v1.0.5 release distributes only plugin artefacts: it contains no broker, OAuth client, callback host, Google account or Drive data. Physical iOS/Android validation stays operator-side; record it with [docs/DEPLOYMENT_EVIDENCE.md](docs/DEPLOYMENT_EVIDENCE.md).

GDrive Streaming is a self-hosted, **read-only** Obsidian mobile plugin for browsing an existing Google Drive knowledge tree. It provides a plugin-owned remote browser, metadata search, and explicit on-demand materialisation of one selected file for iOS and Android. It does not turn remote Drive records into native Obsidian vault files.

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

## Apply this to yourself

Everything below runs on **your** host with **your** Google account. Nothing in this repository points at anybody else's server, account or Drive.

1. **Google Cloud** — create your own project, enable the Drive API, configure a consent screen for your test users, and create a **Web application** OAuth client whose redirect URI is `https://<your-public-host>/gdrive-stream-oauth/google/callback`. You end up with a client ID and a client secret that never leave your host. Details: [GOOGLE_CLOUD_SETUP.md](GOOGLE_CLOUD_SETUP.md).
2. **Test root** — create a dedicated, harmless Drive folder (for example `example-test-root`). Do not start with your real knowledge tree.
3. **Broker** — build and deploy the broker as a system service under its own account, with the isolation and AppArmor templates in `deploy/`. Set `GDRIVE_STREAM_ALLOWED_ROOT_NAME` to your test-root name: the broker has **no default** and refuses to start without it. Follow [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md) end to end, including the post-enable acceptance gate.
4. **Exposure** — publish only the OAuth callback path (`/gdrive-stream-oauth/...`) and keep the pairing/admin routes on your private network. A tunnel or reverse proxy is fine; the pairing API must not be public.
5. **Plugin** — install it on the device (BRAT, links below) and enter **your** broker URL and the **same** test-root name in the plugin settings.
6. **Enrol** — copy the 64-character device fingerprint the plugin shows, mint a one-time code on your broker, paste it, press **Enrol**, and approve the Google request in a browser that is already signed in as the Drive owner. The plugin shows `Waiting for Google consent` until the lease actually arrives, and only then `Enrolled`.
7. **Verify before trusting it** — confirm the metadata listing, the metadata-only search, one explicit download, cache no-overwrite behaviour, and that no create/rename/move/trash/delete request is ever issued. Record non-secret results with [docs/DEPLOYMENT_EVIDENCE.md](docs/DEPLOYMENT_EVIDENCE.md).

> The root name is a two-sided contract. The broker seals it into every device lease and the plugin rejects a lease sealed to a different root. Change it in both places together, and remember the guard is a product-level restriction: Google Drive OAuth is not folder-scoped.

## Install the beta with BRAT

1. In Obsidian, install and enable [BRAT](https://github.com/TfTHacker/obsidian42-brat).
2. In BRAT, choose **Add beta plugin** and enter `AfonsoMoniz1992/obsidian-gdrive-streaming`.
3. Choose **v1.0.5** and enable **GDrive Streaming**.
4. Copy the full 64-character lowercase **Device enrollment fingerprint** shown by the plugin; this exact value is what the broker binds to the one-time code.
5. Configure **your own** HTTPS broker URL and the same harmless test-root name on broker and plugin before enrolling a device.

This release does not grant access to any shared Google account or service. A Google OAuth client in testing mode must be restricted to the operator's intended test users. Do not connect production data; see [STATUS.md](STATUS.md), [SECURITY_DECISION.md](SECURITY_DECISION.md), and [MOBILE_BETA_ACCEPTANCE.md](MOBILE_BETA_ACCEPTANCE.md).

## Troubleshooting the two failures that matter most

- **The consent page opens a sign-in form instead of your account.** In-app browsers (Telegram, Slack, other chat clients) do not share the phone browser's Google session. Long-press the link, copy it, and paste it into Safari or Chrome — or press **Enrol** on the device that owns the Drive account, so the approval opens in its own browser.
- **`Broker transport` while you are on the same network as the broker.** Some routers block device-to-device traffic (client isolation / no hairpin), so the direct private-network path times out while a relayed path works. Use mobile data for the enrolment, or fix the router. Reaching the broker from an unrelated network proves the broker is fine.
- **`Enrolled` appears and then reverts.** That was a real defect before v0.2.5: a pending pairing was rendered as enrolled. On v0.2.5+ the states are honest, and v0.2.6+ re-renders them while the consent window is open.

## Development and verification

```bash
npm ci
npm run verify
```

`npm run verify` runs TypeScript checking, tests, the plugin build, and the broker build. CI also confirms the committed `main.js` is reproducible from source and publishes checksums for release artefacts.

## Documentation

- [scripts/identity_scan.py](scripts/identity_scan.py) — publish gate: spans-based matching over the tree (contents and names), the whole reachable history, commit and tag messages, the Git identity metadata and the release artefacts; requires an out-of-tree deny-list; verdicts PASS / PASS_WITH_DECLARED_EXCEPTIONS / FAIL.
- [scripts/identity-scan-selftest.sh](scripts/identity-scan-selftest.sh) — 18 adversarial scenarios, each checking the gate's exit status.
- [docs/RUNBOOK.md](docs/RUNBOOK.md) — copy-paste runbook: secret generation, service install, routing examples, admin API and verification commands with expected outputs.
- [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md) — generic self-hosting, isolation, OAuth, and recovery procedure.
- [docs/DEPLOYMENT_EVIDENCE.md](docs/DEPLOYMENT_EVIDENCE.md) — non-secret evidence template.
- [ARCHITECTURE.md](ARCHITECTURE.md) — data flow and Obsidian API limits.
- [SECURITY.md](SECURITY.md) and [PRIVACY.md](PRIVACY.md) — security, privacy, and reporting policy.
- [TESTING.md](TESTING.md) and [MOBILE_BETA_ACCEPTANCE.md](MOBILE_BETA_ACCEPTANCE.md) — automated and physical-device acceptance scope.
- [FORK_PROVENANCE.md](FORK_PROVENANCE.md), [UPSTREAM_AUDIT.md](UPSTREAM_AUDIT.md), and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) — upstream provenance and licence notices.

## Provenance and credit

This project is an independently maintained derivative of [solutions-real-it-org/obsidian-drive-on-demand](https://github.com/solutions-real-it-org/obsidian-drive-on-demand), audited at commit [`25f7149789d53672af4b04722d7fedc435cc47ce`](https://github.com/solutions-real-it-org/obsidian-drive-on-demand/commit/25f7149789d53672af4b04722d7fedc435cc47ce).

The upstream project is MIT-licensed by Real-IT / Loïc Bertrand. The required licence and attribution are preserved in [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). This project is **not endorsed by Real-IT or Obsidian**.
