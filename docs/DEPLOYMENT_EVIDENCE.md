# Deployment evidence template

Complete this file for each self-hosted beta deployment. Record no secrets, OAuth codes, token values, Drive URLs or file content.

## Build identity

- Repository commit/tag:
- Plugin manifest version:
- Broker release identifier:
- Reviewer:
- Date/time and timezone:

## Host isolation

- Service account name/UID:
- AppArmor profile label from `/proc/<pid>/attr/current`:
- Broker mount namespace:
- `systemctl --user is-enabled <unit>` (must be not-found or disabled):
- `systemctl is-enabled <unit>` (must be enabled):
- Lingering state (`loginctl show-user ... -p Linger`):
- Legacy user-manager unit/config/state removed or quarantined: yes/no
- Broker process count and owning account (must be exactly one, the service account):
- Production Drive path negative test: BLOCKED / failed
- Test Drive path negative test: BLOCKED / failed
- Listener addresses/ports:
- Rollback drill result:

## OAuth and routing

- Callback endpoint status:
- Pairing endpoint reachability from private network:
- Admin endpoint confirmed non-public:
- Google redirect URI byte-for-byte match: yes/no
- Granted scope exactly `drive.readonly`: yes/no
- Test user/account approved: yes/no

## Functional test root evidence

- Root identifier/name (use a synthetic or redacted value if this template is published):
- Broker root pinned explicitly (no default) and equal to the plugin **Allowed Drive test root**: yes/no
- Metadata list pagination:
- Search is metadata-only:
- One selected-file download:
- Cache no-overwrite behavior:
- No Drive write/move/rename/trash/delete requests observed:
- Logout/re-enrol/revocation result:

## Physical device gates

For each iOS and Android device: OS, Obsidian version, plugin version, OAuth, restart, offline/reconnect, Unicode/deep path, cache cleanup, revoke/re-enrol and observed issue.

## Release decision

- Pass / block:
- Known limitations:
- Independent reviewer decision:
