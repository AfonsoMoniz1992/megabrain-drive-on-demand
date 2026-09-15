# Security policy

## Supported security posture

This is pre-release software. It is supported only for read-only, self-hosted testing against harmless operator-owned data until the gates in [STATUS.md](STATUS.md) pass.

## Security model

- Google Drive remains the source of truth. Plugin metadata and cache are derived state.
- No automatic Drive write, rename, move, trash or deletion exists in the read-only scope.
- Cache removal is local-only; a conflict or missing cache is preferable to silent overwrite.
- The mobile plugin contains no Google client secret and persists no OAuth access/refresh token.
- The broker is pairing/lease-only and must never proxy or log Drive content.
- A self-hosted broker must use a dedicated system account, root-controlled configuration, effective mount isolation and AppArmor enforcing before OAuth consent is authorized.

## OAuth scope

The broker and plugin require exactly `https://www.googleapis.com/auth/drive.readonly` for the implemented existing-tree read-only beta. Do not request `drive`, `drive.file`, or broader scopes for this release. OAuth scopes cannot be constrained to one folder: the allowed-root guard reduces application behavior but is not a substitute for a separate low-risk test account/root.

## Secrets and files

Never put secret values in source, `runtime.env`, GitHub Actions, releases, issue reports, screenshots or chat. Store OAuth client secret, admin token and encryption key in dedicated protected files. The service validates file type, ownership and permissions before binding listeners.

## Reporting a vulnerability

Do not open a public issue for suspected credential disclosure, path-isolation bypass, OAuth/lease weakness, supply-chain compromise or data-exposure issue. Report privately to the repository owner through the contact method shown in the repository's GitHub security policy. Include a minimal reproduction and impact, but never live credentials, tokens, user data or Drive links.

Maintainers acknowledge a report within 7 days where possible, assess severity, coordinate a fix/credit with the reporter, and publish a sanitized advisory after affected operators can act. No version is currently declared production-supported.

## Supply chain

A release must be built from a version-matched tag and include `manifest.json`, `main.js`, `styles.css`, checksums, source verification evidence and a dependency/SBOM review. Upstream code is manually audited; notices remain intact. See [FORK_PROVENANCE.md](FORK_PROVENANCE.md).
