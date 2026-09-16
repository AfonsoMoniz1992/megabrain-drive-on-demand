# Publication plan

The repository is public source for review and self-hosted testing. Publication does not make it BRAT-ready.

## Current policy

- Keep an evidence-based [STATUS.md](STATUS.md) rather than describing source wiring as a deployed product.
- Preserve MIT provenance and the no-endorsement statement in [FORK_PROVENANCE.md](FORK_PROVENANCE.md).
- Publish no operator-specific hostnames, Drive root identifiers or names, account details, OAuth client IDs, secret-record labels or internal paths in public documents. Clearly labelled synthetic examples and blank/redacted evidence templates are permitted.
- A public self-hosted beta may distribute plugin artefacts with explicit limitations, but it must include no shared broker/OAuth configuration and must not claim completed device validation or production readiness.
- Treat Obsidian Community Directory submission as a distinct legal/provenance gate.

The exact release sequence is in [RELEASE.md](RELEASE.md).

## Identity cleanliness scope and residual risk

The public history was rewritten before this release: every reachable commit,
tag object and blob in this repository carries a generic identity, and the
historical file contents use the current generic names. What that does and does
not prove:

- It covers every object reachable from the published refs. It cannot prove the
  absence of objects that GitHub may still serve from earlier force-pushed
  states; treat any previously published commit SHA as public.
- Tags are recreated, not signed, so tag timestamps are not provenance evidence.
  The reproducible build from source is the compensating control.
- If a future change reintroduces an operator-specific value, the scan in
  `docs/RUNBOOK.md` is not automated: re-run the identity scan before publishing.

