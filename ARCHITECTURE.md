# Architecture

## Product boundary

GDrive Streaming is a derivative/self-hosted implementation, not a clean-room claim. Provenance is documented in [FORK_PROVENANCE.md](FORK_PROVENANCE.md).

The project supports a plugin-owned remote experience. It never inserts remote records into Obsidian's vault adapter or metadata index.

```text
Obsidian mobile plugin ── pairing/lease only ──> operator HTTPS broker ──> Google OAuth
Obsidian mobile plugin ── read-only Drive API ──────────────────────────> Google Drive
```

The broker is not a Drive data plane. It does not proxy, cache, search or index the Drive content it serves. The plugin obtains read-only metadata and selected file bytes directly from Google after a device-bound lease is valid.

## Current implementation

- The broker accepts one-time enrollment, completes OAuth callback handling, stores encrypted enrollment/refresh state, and seals short-lived access leases to an enrolled device key.
- The plugin lists metadata, searches its plugin-owned metadata index and downloads a selected file on demand to `_gdrive-stream-cache/by-id/<Drive-ID>/`.
- Cache materialization never overwrites an existing path. Cache cleanup is local-only and must not issue a Drive request.
- The Google scope is exactly `drive.readonly`; no source path implements Drive write, rename, move, trash or delete behavior.
- The selected root name is included in the lease and enforced by `DriveRootScope`. This is a defence-in-depth product filter, not a Google folder-scoped permission.

## Persistence and cache

`data.json` contains only allowlisted non-secret configuration/enrollment metadata plus legacy metadata cache fields. The device identity uses Obsidian SecretStorage. Access/refresh tokens, client secrets, authorization codes, enrollment codes and unsealed leases are not persistable plugin data.

Materialized content remains sensitive local data. Native Obsidian indexing, links, embeds and editors operate only while a file exists locally. Remote-only records cannot appear in File Explorer, Quick Switcher, core Search, graph, Dataview or Canvas.

## Broker deployment boundary

The supported deployment model is a dedicated non-login system account, root-owned code/configuration, protected secret files, an isolated systemd mount namespace and AppArmor enforcing. The host's production and test Drive paths must both be negatively tested from `/proc/<broker-pid>/root/...`; displayed systemd properties are not proof of isolation.

See [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md) for the generic operator procedure and [STATUS.md](STATUS.md) for what remains unverified.
