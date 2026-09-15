# Release procedure

## Publication states

A **public source pre-release** publishes reviewed code and self-hosting documentation only. It does not include a GitHub Release, release assets, or BRAT distribution.

A **distributable public beta** may publish the Obsidian artefact triplet and BRAT instructions only after every prerequisite below is met. It must not claim production readiness.

A **production-use recommendation** requires the public-beta prerequisites plus every gate in [STATUS.md](STATUS.md), including recorded iOS/Android and OAuth evidence plus independent review.

## Public-source checklist

1. Start from a reviewed commit on `main`; run `npm ci && npm run verify`.
2. Confirm `manifest.json`, `package.json`, and `CHANGELOG.md` agree on the source version and publication state.
3. Remove operator-specific hosts, routes, cloud-project identifiers, paths, secrets, personal e-mail addresses, and internal plans from both tree and reachable history before changing visibility.
4. Confirm [FORK_PROVENANCE.md](FORK_PROVENANCE.md) and upstream notices are intact.
5. Publish source only with an explicit notice that BRAT distribution is blocked, if its gates are not satisfied.

## Distributable public-beta prerequisites

1. The OAuth client is not in Google testing mode, or its user/audience restrictions permit the intended public beta without unsafe exceptions.
2. Real Google consent was exercised only against harmless test data and recorded without credentials or tokens.
3. The iOS and Android acceptance cases in [MOBILE_BETA_ACCEPTANCE.md](MOBILE_BETA_ACCEPTANCE.md) have passed and evidence is recorded.
4. An independent reviewer has accepted the non-secret deployment evidence and release notes.
5. `manifest.json`, `package.json`, and the release tag use the same version.
6. Generate `main.js`, `manifest.json`, and `styles.css` from that exact commit; produce SHA-256 checksums and a dependency/SBOM review.
7. Create the GitHub release with the triplet, checksums, and explicit limitations. Download and independently verify the published assets before announcing the release.

BRAT is a beta distribution channel, not a Community Directory approval. Do not submit to the directory until its fork/provenance policy gate is met.
