# Fork / derivative provenance

## Upstream credit

This project derives from [solutions-real-it-org/obsidian-drive-on-demand](https://github.com/solutions-real-it-org/obsidian-drive-on-demand), audited at commit [`25f7149789d53672af4b04722d7fedc435cc47ce`](https://github.com/solutions-real-it-org/obsidian-drive-on-demand/commit/25f7149789d53672af4b04722d7fedc435cc47ce).

The upstream is MIT licensed and attributes copyright to **2026 Real-IT (Loïc Bertrand)**. The applicable MIT notice remains in [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). This repository must preserve those notices in source distributions and releases.

## Purpose of the derivative

The derivative exists so an operator can own and audit the mobile authentication path rather than depend on Real-IT infrastructure. It is not a claim of affiliation, endorsement or support from Real-IT or Obsidian.

## Material changes

- Removed operational reliance on Real-IT domains, OAuth client, callback, claim/refresh endpoints and custom protocol.
- Replaced token persistence with Obsidian SecretStorage plus device-bound encrypted broker leases.
- Added a self-hosted broker deployment model using a dedicated system service account, root-controlled secret files, systemd mount isolation and AppArmor.
- Restricted the initial product scope to read-only Drive operations and explicit cache materialization.
- Added source-level tests, release gates and operator documentation.

See [UPSTREAM_AUDIT.md](UPSTREAM_AUDIT.md) for the technical audit and retained-risk analysis.

## Obsidian Community Directory gate

MIT licensing governs copyright permission; it does not automatically settle an external directory's fork policy. Before a Community Directory submission, maintainers must either obtain publicly verifiable upstream permission or document why the project meets that directory's current independent-work/fork policy. Until then, distribute this project only as an explicitly labelled self-hosted beta.
