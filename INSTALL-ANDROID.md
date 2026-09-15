# Android availability

> **Public source pre-release — no public Android installation is currently supported.** No GitHub Release or BRAT beta is published for this repository.

The Android-compatible plugin source and broker design are available for audit and for an operator's own controlled self-hosting work. Physical Android acceptance and end-to-end Google OAuth consent have **not** been recorded. Do not connect a production knowledge tree.

## Current gate

Do **not** install BRAT or add this repository as a beta plugin. Public distribution is blocked while the Google OAuth client remains in testing mode and while real consent, iOS validation, and Android validation remain incomplete. The authoritative status is [STATUS.md](STATUS.md); the release criteria are in [RELEASE.md](RELEASE.md).

## What a future public beta will require

Before any public Android installation steps are published, an independent review must accept non-secret evidence that:

1. Google consent was completed only against harmless test data.
2. Android pairing, restart, offline/reconnect, cache behaviour, logout, and re-enrolment passed.
3. iOS acceptance also passed, because the release artefact is shared.
4. The operator-hosted broker has completed the isolation and routing checks in [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md).

Google does not support the old out-of-band OAuth flow and an Obsidian plugin cannot add an Android intent filter. The intended design therefore has the operator-hosted broker hold the HTTPS callback and issue short-lived device-bound leases; it does not claim a direct Android OAuth callback.
