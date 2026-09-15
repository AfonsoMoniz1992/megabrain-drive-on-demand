# Changelog

## v0.2.3 — durable mobile enrollment state

### Fixed

- Serialize all plugin `data.json` writes and discard queued stale snapshots. Mobile settings changes can complete asynchronously; an older write no longer overwrites the `pairId` saved after a successful enro...[truncated]

### Fixed

- The settings screen previously displayed a short 16-hex-character label derived from the raw Ed25519 public key, while the broker correctly required the SHA-256 fingerprint of the Ed25519 SPKI DER (64 lowercase hex characters). Enrollment could therefore not be safely approved from the displayed value.
- The plugin now derives the exact canonical broker-compatible fingerprint and displays it in a read-only copyable field. The enrollment code remains pre-bound to that full fingerprint.

## v0.2.1 — public self-hosted beta

### Changed

- Rebuilt the repository as a one-commit public source history after removing deployment-specific names, private routing values, cloud-project identifiers, private paths, personal commit addresses and internal planning material.
- Rewrote documentation for generic self-hosting and a public artefact beta that contains no shared broker, OAuth configuration, account or Drive data.

### Distribution status

- Published as a GitHub/BRAT beta artefact only: every installer must configure an operator-owned broker, Google OAuth client and harmless test root.
- Real Google consent and physical iOS/Android acceptance remain unrecorded. This release is not a production-use recommendation.

## v0.2.0 — self-hosted read-only mobile beta (historical private delivery)

### Added

- Self-hosted broker deployment model: dedicated non-login system account, root-owned release, protected secret files, encrypted runtime state.
- Versioned `systemd` system-service template with mount isolation and an AppArmor enforcing profile.
- Operator-configured broker base URL and operator-configured allowed Drive root name; the plugin ships no default broker host and no default root, and the broker refuses to start unless `GDRIVE_STREAM_ALLOWED_ROOT_NAME` is set explicitly.
- Self-hosting guide, deployment-evidence template, fork provenance, privacy, support, contributing and status documents.

### Not yet verified

- Google consent completion with an operator account.
- Physical Android installation and behavior.
- Physical iOS installation and behavior.

## v0.1.0 — safety foundation

- Controlled plugin identity with no upstream runtime dependency, audited upstream snapshot and retained MIT notice.
- Mobile-compatible Obsidian manifest and reproducible TypeScript/esbuild/Vitest build.
- Read-only Google Drive API primitives behind a disabled connectable release gate.
- Architecture, security, Google Cloud, installation, release, rollback and testing documentation.
