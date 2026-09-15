# Release procedure

## Publication states

A **public self-hosted beta** may publish the reviewed Obsidian artefact triplet and BRAT instructions before physical-device validation is complete **only** when it includes no shared broker, OAuth client, callback host, Google account, Drive root, or test data. It must be clearly labelled unvalidated and not production-ready.

A **production-use recommendation** requires every gate in [STATUS.md](STATUS.md), including recorded iOS/Android and OAuth evidence plus independent review.

## Public-beta checklist

1. Start from a reviewed commit on `main`; run `npm ci && npm run verify`.
2. Confirm `manifest.json`, `package.json`, and `CHANGELOG.md` agree on the release version and beta status.
3. Confirm the tree and reachable history contain no operator-specific hosts, routes, cloud-project identifiers, paths, secrets, personal e-mail addresses, internal plans, OAuth client identifiers, or Drive-root identifiers.
4. Confirm [FORK_PROVENANCE.md](FORK_PROVENANCE.md) and upstream notices are intact.
5. Confirm the release contains no broker configuration, OAuth client configuration, callback URL, token, account information, or Drive data. A test-mode OAuth client stays private to its operator and intended test users.
6. Generate `main.js`, `manifest.json`, and `styles.css` from the exact release commit; produce SHA-256 checksums for that exact triplet.
7. Create the GitHub release with the triplet, checksums, and explicit limitations. Download and independently verify the published assets before announcing the release.
8. State that every installer must configure an operator-owned broker and harmless test root; do not claim iOS/Android validation or production readiness until evidence exists.

BRAT is a beta distribution channel, not a Community Directory approval. Do not submit to the directory until its fork/provenance policy gate is met.
