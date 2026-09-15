# Testing

## Automated verification

Run from a clean checkout:

```bash
npm ci
npm run verify
```

`verify` runs TypeScript checks, the complete Vitest suite, plugin build and broker build. Tests cover read-only Drive boundaries, lease sealing, persistence allowlists, cache no-overwrite behavior, protected secret files, broker routes, systemd/AppArmor templates and release-gate helpers.

Passing automated tests proves source behavior only. It does not prove Google consent, a private network/reverse-proxy routing, AppArmor enforcement on an arbitrary host, or mobile WebView compatibility.

## Required integration/device tests

Follow [docs/DEPLOYMENT_EVIDENCE.md](docs/DEPLOYMENT_EVIDENCE.md) against a harmless test root. Required physical checks include iOS and Android OAuth, plugin restart, offline/reconnect, Unicode/deep paths, selected-file download, cache no-overwrite/cleanup and revoke/re-enrol.

Do not test mutation or production data. Current release status remains in [STATUS.md](STATUS.md).