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

Two different things were cleaned, and they carry different evidence:

- **Historical contents and file names.** Every reachable commit, blob and tag
  message was rewritten, and the whole history uses the project's generic names.
  This is a checked claim: `scripts/identity-scan.sh` scans the working tree, the
  whole reachable history and the release artefacts, and the approval criteria in
  `docs/RUNBOOK.md` section 8 must pass before publishing.
- **Git identity metadata.** Authors, committers and taggers carry the declared
  project policy identity: the name `obsidian-gdrive-streaming` and the
  distributing account's GitHub noreply address. This is enforced by the gate,
  not merely asserted.

The exact claim, so that it can be checked or refuted:

- **enforced:** zero operator-infrastructure identifiers — hostnames, tailnet
  domains, private addresses, cloud project and client ids, Drive ids, secret
  labels, account mailboxes — across the tree, the whole reachable history, the
  commit and tag messages and the Git identity fields;
- **declared exception:** the public account that distributes the plugin. The
  installation instructions must name the slug a user types into BRAT, and the
  Git identity uses that account's noreply address so commits stay attributed.
  The exception is listed with a justification in
  `scripts/identity-exemptions.txt`, and every gate run prints each hit it
  silences together with that justification;
- **not claimed:** that the repository carries no owner identity anywhere. A
  repository published under a personal account cannot claim that without moving
  to a project-owned account. `IDENTITY_REQUIRE_NO_EXEMPTIONS=1` runs the gate in
  strict mode and fails on the declared exception: that failure is the honest
  measure of the difference, and it disappears if you publish from a
  project-owned account.

Residual risk, stated so it is not overread:

- The scan covers every object reachable from the published refs. It cannot prove
  the absence of objects that the host may still serve from earlier force-pushed
  states; treat any previously published commit SHA as public.
- Tags are recreated and unsigned, so tag timestamps and tagger metadata are not
  provenance evidence and are not an identity attestation.
- The reproducible build (a fresh clone rebuilds `main.js` byte-for-byte) covers
  one thing only: that the distributed artefact corresponds to the published
  source. It is not a signature, not a supply-chain attestation, and not proof of
  who built or published it.
- The scan is a detector, not a proof: it finds what its patterns describe. A
  leak in a shape nobody modelled stays invisible, so extend
  `IDENTITY_DENYLIST` for your own host, account, project and chat names.

