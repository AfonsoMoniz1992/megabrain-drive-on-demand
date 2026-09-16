# Changelog

## v0.2.6 — show the waiting-for-consent state while it is happening

### Fixed

- Enrollment state changes are now broadcast to every open surface. The settings screen previously rendered once, so an operator waiting on a Google approval kept reading a stale `Not enrolled` for the whole consent window, with no sign that the pairing was alive.
- The settings screen re-renders on each enrollment state change and unsubscribes when it is closed.

### Added

- An immediate notice when enrolment starts, telling the operator to approve the request in the browser window that just opened.
- A `Check status again` action on the settings screen while a pairing is waiting for consent.

### Notes

- Data-path behaviour is unchanged: no Drive request can happen without a lease, and the pairing window, scope and root checks are untouched.

## v0.2.5 — honest enrollment state and on-demand note opening

### Fixed

- Enrollment now has three truthful states: `Not enrolled`, `Waiting for Google consent` (a pairing exists but no lease has been issued yet) and `Enrolled`. Previously any non-null pairing was rendered as enrolled, so the plugin announced success before Google consent had been granted and then flipped back to not enrolled when the pairing window closed.
- A pairing still waiting for consent is never persisted, so a restart cannot present an authorisation that was never granted.
- The enrollment form is withheld while a pairing waits for consent, so a second one-time code cannot be consumed by accident.
- A pairing that aborts before a lease is granted (rejected code, transport failure, foreign-root lease) is dropped instead of leaving the view stuck on `Waiting for Google consent`.
- The settings screen offers the code field only from a settled not-enrolled state, matching the browser view.

### Added

- Clicking a note in the read-only browser now opens it right after the on-demand download, instead of only reporting the local cache path.
- Settings display the **effective** broker base URL and Drive test root used for requests, and a value that cannot be stored raises a visible notice instead of silently failing closed.
- Failure notices include the effective broker base URL and root, so a truncated URL or a value pasted into the wrong field is visible in the error itself.

### Notes

- Broker pairing, lease, scoped root and read-only boundaries are unchanged.

## v0.2.4 — preserve mobile enrollment on no-op settings events

### Fixed

- Ignore mobile settings callbacks whose broker URL or allowed root is semantically unchanged after validation and normalization. Such callbacks no longer rebuild the client or clear the persisted non-secret `pairId` when an operator returns to Settings.
- Preserve the fail-closed boundary for genuine configuration changes: changing the effective broker URL or allowed Drive root still clears the pairing and requires a new device enrollment.

## v0.2.3 — durable mobile enrollment state

### Fixed

- Serialize all plugin `data.json` writes and discard queued stale snapshots. Mobile settings changes can complete asynchronously; an older write no longer overwrites the `pairId` saved after a successful enro...[truncated]

## v0.2.2 — canonical device enrollment fingerprint

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
