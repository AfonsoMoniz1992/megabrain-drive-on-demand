# Desktop beta installation

> **Public self-hosted beta v1.0.6 — not production-ready.** The release contains plugin artefacts only; it includes no broker, Google OAuth client, callback host, account, token, or Drive data.

## Install with BRAT

1. Open a disposable/test vault in Obsidian desktop.
2. Install and enable [BRAT](https://github.com/TfTHacker/obsidian42-brat).
3. Choose **Add beta plugin**, enter this repository's `owner/repository` identifier, select **v1.0.6**, then enable the plugin.
4. Copy the full 64-character lowercase **Device enrollment fingerprint** shown in settings.
5. Configure an operator-owned broker and a harmless test root before attempting enrollment.

Do not enter a client secret in Obsidian and do not connect production data. The same operator-owned Google OAuth and broker safeguards described in [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md) apply.

## Development

```bash
npm ci
npm run verify
```

A production recommendation still requires all evidence in [STATUS.md](STATUS.md).

If the consent page opens a sign-in form, or enrolment fails with `Broker transport`, see the troubleshooting section in [README.md](README.md#troubleshooting-the-two-failures-that-matter-most).
