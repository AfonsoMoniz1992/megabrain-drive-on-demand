# Self-hosting guide

This guide deploys the **mobile OAuth broker only**. It is for a Linux operator who owns the Google Cloud OAuth client and the Drive account. It deliberately starts with harmless test data and read-only access.

## 1. Prerequisites

- Linux with systemd and AppArmor enforcing.
- Node.js version supported by this repository's lockfile.
- A public HTTPS callback endpoint controlled by the operator. The pairing API must be reachable only over the operator's private network. A reverse proxy or tunnel may serve the callback, but do not expose pairing or admin endpoints publicly.
- A dedicated Google Cloud project with Google Drive API enabled.
- A dedicated harmless Drive folder with a unique name; do not point at a production knowledge tree. Its exact name is configured in **both** the broker (`GDRIVE_STREAM_ALLOWED_ROOT_NAME`) and the plugin settings (**Allowed Drive test root**); the plugin refuses a lease sealed to any other root.
- Root access for the host. Do not run the broker under a desktop/login account.

## 2. Google OAuth configuration

Create a **Web application** OAuth client because the broker owns the HTTPS callback. Configure:

- Redirect URI: `https://<your-public-host>/gdrive-stream-oauth/google/callback`
- Scope: exactly `https://www.googleapis.com/auth/drive.readonly`
- Audience/test users: only the intended test users during beta.

The client ID is non-secret. Keep the client secret only in a protected server-side secret file. Google scopes are not folder-scoped: the test root is an application guard, not a Google authorization boundary.

## 3. Build a reviewed release

```bash
npm ci
npm run verify
```

Copy the reviewed runtime to a root-owned release directory, for example:

```text
/opt/gdrive-stream-broker/releases/<version-or-commit>/
/opt/gdrive-stream-broker/current -> releases/<version-or-commit>
```

The broker release and symlink must be owned by root and not writable by the service account.

## 4. Service identity, config and secrets

Create a non-login system account named `gdrive-stream-broker` (or adapt the versioned unit consistently). Install:

- `deploy/systemd/gdrive-stream-broker.system.service` to `/etc/systemd/system/gdrive-stream-broker.service` (rename on install so the unit name matches the commands below);
- `deploy/apparmor/gdrive-stream-broker` to `/etc/apparmor.d/`;
- a non-secret runtime file at `/etc/gdrive-stream-broker/runtime.env`;
- secret files under `/etc/gdrive-stream-broker/secrets/`;
- encrypted runtime state at `/var/lib/gdrive-stream-broker/`.

Do not install this as a `systemd --user` service. A user-manager unit cannot provide the required mount isolation for a home-mounted Drive tree: the directives are accepted but the broker can still reach the production root through its own namespace. Only a system service with a dedicated account and an explicit negative test is acceptable.

Start from [`deploy/runtime.env.example`](../deploy/runtime.env.example). The runtime file contains paths and public configuration, never secret values. `GDRIVE_STREAM_ALLOWED_ROOT_NAME` is **required**: the broker has no default root and refuses to start without it, so a misconfigured deployment fails closed instead of silently sealing a folder nobody chose. Secret files should be `root:gdrive-stream-broker` mode `0440`; the service refuses unsafe ownership/mode combinations. Keep state owned by the service account and mode `0700`.

## 5. Retire any legacy installation first

A previously deployed `systemd --user` broker **must be stopped, disabled and removed before the system service is enabled**. A user unit accepts the isolation directives but cannot enforce them for a home-mounted Drive tree, and if it stays enabled while lingering is on it wins the loopback ports after a reboot and the isolated service never starts.

Never enable the system service while the legacy unit is still enabled: the two would overlap on the same loopback ports and the unisolated broker could keep serving. Retire the legacy unit, verify the retirement, and only then enable the system service in [step 6](#6-enforce-isolation-before-oauth).

```bash
# 1. Stop and disable the legacy user-manager unit, then delete it and its enablement link.
systemctl --user stop gdrive-stream-broker.service
systemctl --user disable gdrive-stream-broker.service
rm -f ~/.config/systemd/user/gdrive-stream-broker.service
rm -f ~/.config/systemd/user/default.target.wants/gdrive-stream-broker.service
systemctl --user daemon-reload

# 2. Move legacy release, config and state out of the login account's reach.
sudo mkdir -p /root/gdrive-stream-legacy-removed
sudo mv ~/.config/gdrive-stream-broker        /root/gdrive-stream-legacy-removed/home-config
sudo mv ~/.local/share/gdrive-stream-broker   /root/gdrive-stream-legacy-removed/home-state
sudo mv ~/.local/opt/gdrive-stream-broker     /root/gdrive-stream-legacy-removed/home-release
sudo chmod -R go-rwx /root/gdrive-stream-legacy-removed

# 3. Fail-closed gate: every proof must hold before the system service is enabled.
#    Each query is classified explicitly. A recognised answer proves a fact; an empty or
#    unrecognised answer aborts. An unanswered query is never treated as a passing value.
abort() { printf 'ABORT: %s\n' "$1" >&2; exit 1; }

# MainPID is numeric whenever the query succeeds. 0 means the system service is not running
# yet, which is the normal pre-enable state. An unreadable value would silently disable the
# self-exclusion below, so treat it as a failure instead.
system_main_pid=$(systemctl show -p MainPID --value gdrive-stream-broker.service 2>/dev/null) \
  || abort "cannot query the system service MainPID"
case "$system_main_pid" in ''|*[!0-9]*) abort "unusable system service MainPID '${system_main_pid}'" ;; esac

# is-enabled and is-active exit non-zero for perfectly valid answers (disabled, inactive),
# so judge these by the printed value only, and treat an empty answer as a query failure.
user_unit_enabled=$(systemctl --user is-enabled gdrive-stream-broker.service 2>/dev/null) || true
user_unit_active=$(systemctl --user is-active gdrive-stream-broker.service 2>/dev/null) || true

# pgrep: status 0 means candidates were found, 1 means none, anything else is a real failure.
if candidates=$(pgrep -f 'broker/dist/index\.js' 2>/dev/null); then
  :
else
  pgrep_status=$?
  [ "$pgrep_status" -eq 1 ] || abort "pgrep failed with status $pgrep_status"
  candidates=""
fi

stray_broker_pids=""
for pid in $candidates; do
  [ "$pid" = "$system_main_pid" ] && continue
  # Classify by process name rather than by giving up on an unreadable name, so a shell that
  # merely mentions the entrypoint path in its own command line cannot count as a broker.
  comm=$(cat "/proc/$pid/comm" 2>/dev/null) || abort "cannot classify pid $pid (/proc/$pid/comm unreadable)"
  case "$comm" in
    # Node names its main thread 'node-MainThread' on some builds, so match the whole family.
    node|nodejs|node-*|nodejs-*) stray_broker_pids="$stray_broker_pids $pid" ;;
  esac
done
stray_broker_pids=${stray_broker_pids# }

printf 'user_unit_is_enabled=%s\n' "$user_unit_enabled"
printf 'user_unit_is_active=%s\n' "$user_unit_active"
printf 'stray_broker_pids=%s\n' "${stray_broker_pids:-none}"
printf 'linger=%s\n' "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null || echo unknown)"

case "$user_unit_enabled" in
  not-found|disabled) ;;
  '') abort "the user manager did not answer 'systemctl --user is-enabled' (unit removed, or user manager unreachable?)" ;;
  *) abort "legacy user unit is still enabled ('$user_unit_enabled')" ;;
esac
case "$user_unit_active" in
  inactive) ;;
  '') abort "the user manager did not answer 'systemctl --user is-active'" ;;
  *) abort "legacy user unit is still active ('$user_unit_active')" ;;
esac
[ -z "$stray_broker_pids" ] || abort "stray broker processes exist ($stray_broker_pids)"

printf 'migration_gate=PASS (pre-enable snapshot)\n'
```

Record the printed gate values as evidence. `migration_gate=PASS` proves all three facts at the instant it ran: the user unit answers `not-found` or `disabled`, it answers `inactive`, and no stray broker process exists. It is a **pre-enable snapshot, not an atomic exclusion** — a legacy or manually started broker can still appear between this check and the enable command in the next step, which is why step 6 repeats the check immediately after enabling. Any unproven or unanswerable condition makes the gate exit non-zero, so a failed query is never mistaken for a passing value.

Isolation may be claimed only from the negative tests against the **system** service PID, and only with exactly one broker process running under the service account.

## 6. Enforce isolation before OAuth

Load the AppArmor profile, then enable/restart the system service. Do not run this until [step 5](#5-retire-any-legacy-installation-first) printed `migration_gate=PASS`.

```bash
sudo apparmor_parser -r /etc/apparmor.d/gdrive-stream-broker
sudo systemctl daemon-reload
sudo systemctl enable --now gdrive-stream-broker.service
```

### 6b. Post-enable acceptance (blocking)

Step 5's gate is a snapshot taken **before** the command above, so nothing about the accept state may be assumed. Prove it immediately.

Step 6b is a versioned, tested gate rather than a snippet to paste: `deploy/post-enable-acceptance.sh`. Run it from the checkout immediately after the command above. It needs `sudo` for `systemctl`, for `/proc/<pid>/environ`, and for `ss`, because an unprivileged `ss` cannot attribute sockets to another user's process and would fail open with an empty owner list.

```bash
bash deploy/post-enable-acceptance.sh
```

It prints `expected_listener_ports=...` and then either `post_enable_acceptance=PASS` with exit status `0`, or `ABORT: ...` with a non-zero status. Every failure stops the service and confirms it is `inactive`, printing `STOP FAILED` if the stop itself did not take effect.

The four expected ports are read from the environment of the **running process**, not from the configuration file: `/proc/<MainPID>/environ` holds exactly what systemd built from `EnvironmentFile=`, so quoting, escaping, line continuations and the last-assignment rule are never re-implemented here and can never disagree with what the broker received. A variable absent from that environment falls back to the documented default; a variable that is present but unusable — non-numeric, empty, outside 1024–65535, or duplicating another port — stops the service instead of quietly becoming a default. `tests/deploy-post-enable-acceptance.test.ts` covers the effective-value case, the default fallback, present-but-invalid and duplicate ports, an unreadable environment, a listener owned by another process, and a failing query.

A correct deployment must then prove all of the following from the running broker PID:

1. the service UID is `gdrive-stream-broker`, not the desktop/login user;
2. `systemctl is-enabled gdrive-stream-broker.service` reports `enabled` while `systemctl --user is-enabled` reports `not-found` or `disabled`;
3. AppArmor reports `gdrive-stream-broker (enforce)`;
4. the process has a distinct mount namespace;
5. `/proc/<pid>/root/<production-drive-path>` is inaccessible;
6. `/proc/<pid>/root/<test-drive-path>` is inaccessible;
7. only the documented loopback listeners are open, and exactly one broker process is running.

The template uses `ProtectHome=tmpfs`, which blocks home-mounted Drive roots. If your Drive mount lies outside `/home`, add an explicit `InaccessiblePaths=` rule for it and repeat the PID-namespace negative test. Do not accept `systemctl show` output alone as proof.

## 7. Routing and exposure

Keep the admin endpoint loopback-only. Expose only the required callback and pairing routes. If using a private network, verify separately:

- callback route receives HTTPS at the configured public path;
- pairing route is private network-only;
- no admin route is public;
- redirect URI exactly matches Google Cloud configuration.

A host firewall/proxy should restrict broker egress to the required Google OAuth/Drive endpoints and resolver. The supplied AppArmor profile constrains socket families but is not a domain-aware egress firewall.

## 8. Integration and recovery

Use only the harmless test root for the first consent. Set **Allowed Drive test root** in the plugin settings to exactly the `GDRIVE_STREAM_ALLOWED_ROOT_NAME` value configured on the broker — a mismatch pairs successfully but never returns a lease the plugin will accept. Confirm the granted scope is exactly `drive.readonly`, list metadata, download one selected file and verify no Drive mutation occurs. Complete [DEPLOYMENT_EVIDENCE.md](DEPLOYMENT_EVIDENCE.md).

For an update: build and verify a new release, atomically repoint `current`, restart, repeat the health and negative-access tests, and retain the preceding release until recovery is proven. To roll back, repoint `current` to the prior release and restart. Never delete state or production data as part of a rollback.

## 9. Uninstall / incident response

On suspected compromise: revoke affected Google access through the operator account, revoke broker enrollment, stop the service, preserve sanitized logs/evidence, and rotate the client secret, admin token and encryption key. Do not paste secret material into issue reports. For clean uninstall, stop/disable the service, remove routes, then remove service/release/config/state only after preserving a rollback copy and confirming it contains no needed enrollment evidence.
