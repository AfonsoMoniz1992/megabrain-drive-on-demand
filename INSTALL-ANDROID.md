# Android beta installation

> **Public self-hosted beta v0.2.6 — Android validation is pending.** The release contains only plugin artefacts. It includes no broker, Google OAuth client, callback host, account, token, or Drive data.

Use only a disposable local vault, an operator-owned broker, and harmless test data. Do not connect a production knowledge tree.

## Install with BRAT

1. Install Obsidian from Google Play and open a dedicated test vault.
2. Install and enable [BRAT](https://github.com/TfTHacker/obsidian42-brat).
3. In BRAT choose **Add beta plugin**, enter this repository's `owner/repository` identifier, then select **v0.2.6**.
4. Enable **GDriveStreaming Drive on Demand**.
5. Copy the full 64-character lowercase **Device enrollment fingerprint** shown in settings. The broker binds the one-time code to this exact value.
6. Configure your own HTTPS broker URL and **Allowed Drive test root**. The root name must match the one configured in your broker's `GDRIVE_STREAM_ALLOWED_ROOT_NAME`.
7. Enrol only through your own broker and test Google OAuth client. A test-mode client must remain restricted to your intended test users.

## Required acceptance before production use

Android pairing, restart, offline/reconnect, cache behaviour, logout, and re-enrolment are **not yet recorded** for this public beta. Follow [MOBILE_BETA_ACCEPTANCE.md](MOBILE_BETA_ACCEPTANCE.md), record only non-secret evidence in [docs/DEPLOYMENT_EVIDENCE.md](docs/DEPLOYMENT_EVIDENCE.md), and keep use limited to harmless test data.

Google does not support the old out-of-band OAuth flow and an Obsidian plugin cannot add an Android intent filter. The operator-hosted broker holds the HTTPS callback and issues short-lived device-bound leases; the plugin does not claim a direct Android OAuth callback.
