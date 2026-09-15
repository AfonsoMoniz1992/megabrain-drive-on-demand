# Desktop availability

> **Public source pre-release — no public plugin distribution is currently supported.** No GitHub Release or BRAT beta is published for this repository.

The source is public for audit and controlled self-hosting. The implementation is read-only by design, but no production use is approved and no public installation channel is available until the release gates pass.

## Current gate

Do **not** add this repository to BRAT. Public BRAT distribution is blocked while Google OAuth consent and the required iOS/Android acceptance evidence are incomplete. See [STATUS.md](STATUS.md), [SECURITY_DECISION.md](SECURITY_DECISION.md), and [RELEASE.md](RELEASE.md).

## Development only

A maintainer or self-hosting operator may build and inspect the source locally with:

```bash
npm ci
npm run verify
```

Do not enter a client secret in Obsidian. A future public beta, if its gates pass, will publish version-matched `manifest.json`, `main.js`, `styles.css`, and checksums through a tagged GitHub release.
