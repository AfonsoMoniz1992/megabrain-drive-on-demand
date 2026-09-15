# Changelog

## v0.2.1 — public source pre-release (unreleased)

### Changed

- Rebuilt the repository as a one-commit public source history after removing deployment-specific names, private routing values, cloud-project identifiers, private paths, personal commit addresses and internal planning material.
- Rewrote the public documentation around generic self-hosting and a clear source-versus-distribution release gate.

### Distribution status

- **No GitHub Release and no BRAT beta are published for `v0.2.1`.**
- Public BRAT distribution remains blocked while the Google OAuth client is in testing mode and real Google consent plus iOS/Android validation are not recorded in [STATUS.md](STATUS.md).

## v0.2.0 — self-hosted read-only mobile beta (historical private delivery)

### Added

- Self-hosted broker deployment model: dedicated non-login system account, root-owned release, protected secret files, encrypted runtime state.
- Versioned `systemd` system-service template with mount isolation and an AppArmor enforcing profile.
- Operator-configured broker base URL and operator-configured allowed Drive root name; the plugin ships no default broker host and no default root, and the broker refuses to start unless `GDRIVE_STREAM_ALLOWED_ROOT_NAME` is set explicitly.
- Self-hosting guide, deployment-evidence template, fork provenance, privacy, support, contributing and status documents.
- Runtime secret loading that accepts either service-owned `0600` files or root-owned service-group-readable files.

### Fixed

- The operator-configured root is now honoured end to end. Previously the broker sealed `GDRIVE_STREAM_ALLOWED_ROOT_NAME` into each lease while the plugin still resolved and validated a hard-coded folder name, so a self-hosted operator using any other test root could pair successfully but never obtain a usable lease. The plugin now has a persisted **Allowed Drive test root** setting wired into both root resolution and lease validation, and it rejects path-like or traversal values.

### Changed

- Documentation rewritten around an evidence-based release status instead of presenting source wiring as a deployed product.
- The plugin now discards any existing pairing identifier when the broker origin changes.
- Settings UI and documentation now distinguish broker-assisted pairing from direct plugin-to-Google Drive reads.

### Removed

- The `systemd --user` broker unit. A user-manager unit accepts isolation directives but the broker could still reach a home-mounted production Drive root from its own namespace.
- Personal hostnames, Drive names and secret-record references from documentation.

### Not yet verified

- Google consent completion with an operator account.
- Physical Android installation and behavior.
- Physical iOS installation and behavior.

This historical version was not BRAT-ready or production-ready. The public tree does not publish it as a release.

## v0.1.0 — safety foundation

- Controlled plugin identity with no upstream runtime dependency, audited upstream snapshot and retained MIT notice.
- Mobile-compatible Obsidian manifest and reproducible TypeScript/esbuild/Vitest build.
- Read-only Google Drive API primitives behind a disabled connectable release gate.
- Architecture, security, Google Cloud, installation, release, rollback and testing documentation.
