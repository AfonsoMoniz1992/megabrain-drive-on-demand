# Rollback

## Plugin

A plugin rollback changes only the local plugin build. It must not issue Drive mutations. Preserve the existing `_gdrive-stream-cache/` until the operator identifies it as plugin-owned derived data; local cache removal is not remote deletion.

Restore a previously verified version-matched `manifest.json`, `main.js` and `styles.css`, restart Obsidian, and test against the harmless root before re-enrolment.

## Broker

Keep the prior root-owned release directory and systemd unit backup. To roll back: atomically repoint `/opt/gdrive-stream-broker/current` to the prior release, restart the system service, then verify active status, AppArmor label, listeners and both PID-namespace Drive-path denials. Do not delete encrypted state, secrets or audit evidence during rollback.

If isolation cannot be proven, stop the broker and revoke/disable exposure rather than weakening the sandbox. See [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md).