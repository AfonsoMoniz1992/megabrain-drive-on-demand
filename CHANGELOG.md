# Changelog

## v1.0.5 — fifth-review fixes (the gate is rewritten, not patched)

The scan was rewritten from shell to Python because five of the defects found in
review were consequences of doing regex work by piping text through `grep`, `sed`
and `cut`. Matching now works on spans.

### Fixed

- **Truncation before analysis.** The shell version cut every candidate line to 180 characters *before* classifying it, so a forbidden value further along the line was never examined — on the tree and on the artefacts. Nothing is truncated before analysis now.
- **Partial overlap.** An exemption matching only part of a forbidden value (a prefix, or a value sharing a line) could leave the remainder unmatched and be treated as clean. A match is exempt only when its **whole** span is covered by a declared exemption; partial cover is a hit.
- **Exemptions via `sed`.** A pattern containing the delimiter used by the masking step behaved inconsistently. Matching no longer builds a second regex out of the first.
- **Deny-lists that fail open.** An empty, comment-only or invalid deny-list was treated as "present" and could yield a pass. The gate now requires at least one valid pattern, rejects invalid regexes, and exits 2 as a configuration error.
- **Path exclusions built as regexes.** The two excluded paths were matched as unescaped regexes, so a near-identical sibling name was also excluded. There are no path exclusions inside the tree any more: file names and contents are both scanned.
- **File and directory names were never scanned.** An identifier in a file name passed; names are now a scanned surface, in the tree and in history.
- **Identity metadata could be silenced by an exemption.** Matches in the Git identity fields are now reported as `KNOWN-IDENTITY-EXCEPTION` and force the verdict to `PASS_WITH_DECLARED_EXCEPTIONS`, so a plain `PASS` can never hide the declared account.
- **The self-test did not check exit status.** Every scenario asserted only on output text, so a gate that printed `FAIL` and returned success would have passed. Each of the 18 scenarios now checks the exit status *and* the expected output, and the scenarios cover every defect above: missing, empty, comment-only and invalid deny-lists; identifiers planted in another file, in a file name, and under the tool's own basename elsewhere; co-location and partial overlap; a forbidden value 400 characters into a line; an exemption pattern containing a path separator; a leak present in history but removed from the tree; metadata outside the policy; metadata matching a declared exemption; and smoke-mode flagging.

### Added

- CI runs the gate self-test and a non-authoritative built-in-pattern scan on every push (`.github/workflows/verify.yml`). The authoritative run stays manual because it needs an operator deny-list, which must live outside the tree.

### Changed

- Verdicts are now `PASS`, `PASS_WITH_DECLARED_EXCEPTIONS` or `FAIL`; exit status 0 / 0 / 1, with 2 for configuration errors. `docs/RUNBOOK.md` section 8 and `PUBLICATION_PLAN.md` were rewritten so each claim matches what the gate proves, including what is deliberately not scanned.

## v1.0.4 — fourth-review fixes (gate could pass while hiding things)

### Fixed

- **Strict mode now fails as published.** It failed only when an exemption happened to be used, so running it as-is passed and the claim was false. It now fails when an exemption is *used* **and** when one is *declared*, printing both reasons.
- **A deny-list is now required for an authoritative run.** Without one the gate proves only its built-in patterns, so it fails instead of reporting a pass; `IDENTITY_ALLOW_NO_DENYLIST=1` allows an explicitly non-authoritative smoke run.
- **Exemptions can no longer hide a co-located identifier.** Masking is per identifier instead of per line: the exempted substring is removed and the remainder of the line is re-scanned, so a forbidden identifier sharing a line with an exempted value is reported.
- **The declared directory exclusions are reported, not implied.** `.git` and `node_modules` are listed with counts on every run, together with the note that released artefacts are scanned separately, which is where bundled content surfaces.

### Added

- `scripts/identity-scan-selftest.sh`: ten adversarial scenarios against a disposable fixture, including the two bypasses found in review (co-located identifier on an exempted line; identifier planted under the scanner's own basename at another path). Fixture identifiers are generated at run time, so the test file needs no exclusion from the scan it exercises.

### Changed

- `docs/RUNBOOK.md` section 8 and `PUBLICATION_PLAN.md` rewritten so every claim matches the gate's actual behaviour, including the required deny-list and the exact list of exclusions.

## v1.0.3 — third-review fixes (gate hardening and exact claims)

### Fixed

- `scripts/identity-scan.sh` now scans at line level, so an exemption is judged against the offending line instead of the file name — the previous design could not silence anything.
- The deny-list is applied to the Git identity fields (author, committer, tagger) and not only to file contents.
- The self-exclusion is now an exact path (`scripts/identity-scan.sh`) plus the exemptions file; the previous basename-wide exclusion is gone, and a planted file at another path is detected (regression test in the runbook).
- An exemption line without a justification now fails the gate.
- Runbook secret generation uses `openssl rand -hex 32` instead of `xxd`, which is not present on every distribution, and the prerequisites are declared.
- Runbook Tailscale explanation replaced with what the CLI actually answers on 1.102.x for the legacy forms (`the CLI for serve and funnel has changed`, `invalid argument format`, and `off` still parsed).

### Added

- `scripts/identity-exemptions.txt`: the declared public exception (the distributing account), each entry with a justification, printed by every gate run as `EXEMPT ... <= why`.
- `IDENTITY_REQUIRE_NO_EXEMPTIONS=1` strict mode, which fails on any exemption and reports exactly what carries the difference.

### Changed

- `PUBLICATION_PLAN.md` states the claim in three parts — what is enforced, the one declared exception, and what is explicitly **not** claimed — instead of asserting a generic identity for everything.

## v1.0.2 — second-review fixes (identity metadata and runbook execution paths)

### Fixed

- **Git identity metadata**: authors, committers and taggers now carry the project policy identity (project name plus a GitHub noreply address). The previous personal name is gone from every reachable commit and tag object.
- `CHANGELOG.md` no longer contains the literal truncation marker that the previous entry quoted.
- `docs/RUNBOOK.md` secret-file permission rule and the expected callback response now match the implementation exactly.

### Added

- `scripts/identity-scan.sh`: publish gate that scans the working tree, every reachable commit, blob, commit message and tag message, the release artefacts and the Git identity metadata, with explicit approval criteria and a non-zero exit on any hit.
- `docs/RUNBOOK.md` section 8 documents that gate, its criteria and why the deny-list must live outside the tree.
- `docs/RUNBOOK.md` section 3 builds the broker (`npm ci`, `npm run verify`, `npm run broker:build`) before installing, because the unit starts an output that is not committed.

### Changed

- `docs/RUNBOOK.md` routing uses the current Tailscale CLI form (`sudo`, no trailing `on`/`off` toggle) and documents the funnel/serve split.
- `docs/RUNBOOK.md` section 7 documents a complete `token-key` rotation, archiving the state sealed with the old key, instead of a restart-and-re-enrol note that would leave the service in a restart loop.
- `PUBLICATION_PLAN.md` separates the checked historical-content cleaning from the declared Git identity policy, and limits the reproducible-build claim to artefact-to-source correspondence.

## v1.0.1 — review fixes, runbook and distribution notices

### Fixed

- Removed the literal truncation markers that had been committed into `README.md`, `STATUS.md` and `CHANGELOG.md`, replacing them with the intended sentences.

### Added

- `docs/RUNBOOK.md`: copy-paste runbook covering secret generation, the non-secret runtime file, service installation, routing examples, the admin API (enrolment, status, revocation) and verification commands with their expected non-secret outputs.
- Third-party notices for the libraries bundled into the published `main.js` (`@noble/ciphers`, `@noble/curves`, `@noble/hashes` 2.4.0, MIT), with the full licence text.
- `LICENSE` and `THIRD_PARTY_NOTICES.md` now ship as release assets alongside the plugin artefacts.

### Changed

- Historical file contents were rewritten so the entire reachable history uses the generic identity, not only the current commit.
- `PUBLICATION_PLAN.md` now states the identity-cleanliness scope and its residual risk (force-pushed objects may still be served by the host; tags are recreated, not signed).

## v1.0.0 — first public, generic release

### Changed

- Renamed the project to **GDrive Streaming** (`obsidian-gdrive-streaming`) and made every internal identifier generic: `GDRIVE_STREAM_*` environment variables, `gdrive-stream-broker.service`, service account `gdrive-stream-broker`, install roots `/opt`, `/etc` and `/var/lib/gdrive-stream-broker`, AppArmor profile `gdrive-stream-broker`, plugin id `obsidian-gdrive-streaming` and cache directory `_gdrive-stream-cache`.
- Rewrote commit authorship so the public history carries no operator-specific network name.
- Documentation now reads as a generic recipe: no hostname, project ID, account, OAuth client ID, secret-file label or Drive identifier from the reference deployment appears anywhere in the repository.
- Added operator troubleshooting for the two failures that cost the reference deployment the most time: a consent page that opens without the Drive owner's session, and a broker that is unreachable from the same LAN while mobile data works.

### Notes

- Behaviour is otherwise identical to v0.2.6.
- The plugin id changed, so an existing installation must be removed and re-added; enrolment state does not carry over to the new id.

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

- Serialize all plugin `data.json` writes and discard queued stale snapshots. Mobile settings changes can complete asynchronously; an older write no longer overwrites the `pairId` saved after a successful enrolment.

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
