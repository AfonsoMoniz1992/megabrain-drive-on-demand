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
  This is a checked claim: `scripts/identity_scan.py` scans the working-tree contents
  and names, the whole reachable history and its paths, commit and tag messages,
  and the release artefacts; the approval criteria are in `docs/RUNBOOK.md`
  section 8.
- **Git identity metadata.** Authors, committers and taggers carry the declared
  project policy identity: the name `obsidian-gdrive-streaming` and the
  distributing account's GitHub noreply address. This is enforced by the gate,
  not merely asserted.

The exact claim, so that it can be checked or refuted:

- **enforced:** zero hits for the operator's out-of-tree deny-list and for the
  built-in patterns (tailnet domains, private addresses, consumer mailboxes,
  Google OAuth client ids, Drive links, service accounts) across working-tree
  contents and file names, the whole reachable history and its paths, commit and
  tag messages, the Git identity fields and the release artefacts. An
  authoritative run requires that deny-list: without one the gate reports a
  configuration error instead of a pass.
- **declared exception:** the public account that distributes the plugin. A
  repository published under one cannot claim to carry no owner identity: the
  installation instructions must name the slug a user types into BRAT, and the
  Git identity uses that account's noreply address so commits stay attributed.
  The exception is listed with a justification in `scripts/identity-exemptions.txt`;
  every masked hit is printed with that justification, and a match in the Git
  identity metadata is reported as a known exception rather than silenced. The
  verdict for this repository is therefore `PASS_WITH_DECLARED_EXCEPTIONS`, never
  a plain `PASS`.
- **not claimed:** that the repository carries no owner identity anywhere, and
  that the gate proves absence rather than detecting what its patterns describe.
  `IDENTITY_REQUIRE_NO_EXEMPTIONS=1` fails in every configuration for this
  repository and prints every reason; that failure is the honest measure of the
  difference, and it disappears if you publish from a project-owned account and
  declare nothing.
- **scope decisions, not gate properties:** `.git` and `node_modules` are not
  scanned (neither is distributed; content that reaches a release is caught by the
  artefact surface), and the authoritative run is a manual step with an operator
  deny-list — CI runs the gate self-test and a non-authoritative built-in-pattern
  scan on every push.

The gate's behaviour is tested rather than asserted: `scripts/identity-scan-selftest.sh`
runs 18 adversarial scenarios against a disposable fixture, each checking the exit
status and the expected output, including identifiers planted only in a file name,
co-located or partially overlapping with an exempted value, and a leak present in
history but removed from the tree.

