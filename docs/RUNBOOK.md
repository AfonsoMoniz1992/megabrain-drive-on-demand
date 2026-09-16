# Operator runbook (copy-paste)

Command-first companion to [SELF_HOSTING.md](SELF_HOSTING.md). Replace every
`<angle-bracketed>` value. Nothing here contains an operator hostname, account,
project ID, client ID, secret or Drive identifier.

## 0. What you need

- A host you control with systemd and AppArmor in enforcing mode.
- **Node.js 22** (the version CI builds and tests with): `node --version`.
- `openssl`, `grep`, `git` and `curl` on the host. No Python or `jq` is needed;
  secret generation below uses `openssl` rather than `xxd`, which is not present
  on every distribution.
- Your own Google Cloud project, OAuth client and Drive test folder
  ([GOOGLE_CLOUD_SETUP.md](../GOOGLE_CLOUD_SETUP.md)).
- A way to publish one HTTPS path to the internet and one path to your private
  network only (a tunnel such as Tailscale Serve, or a reverse proxy).

Ports used by the broker (all loopback):

| Port | Role | Exposed to |
|---|---|---|
| `34003` (`PORT`) | Broker API: `/oauth/pair`, `/oauth/claim`, `/oauth/nonce`, `/oauth/lease` | nothing |
| `34004` (`GDRIVE_STREAM_ADMIN_PORT`) | Admin API: `/admin/enrollment`, `/admin/revoke` | nothing |
| `34005` (`GDRIVE_STREAM_GATEWAY_PORT`) | Public gateway: forwards **only** the exact callback path | public HTTPS path |
| `34006` (`GDRIVE_STREAM_PRIVATE_GATEWAY_PORT`) | Private API gateway: pairing/claim allow-list | private network only |

## 1. Create the service account and secrets

```bash
sudo useradd --system --no-create-home --home-dir /var/lib/gdrive-stream-broker \
  --shell /usr/sbin/nologin gdrive-stream-broker
sudo install -d -m 0750 -o root -g gdrive-stream-broker /etc/gdrive-stream-broker
sudo install -d -m 0750 -o root -g gdrive-stream-broker /etc/gdrive-stream-broker/secrets
sudo install -d -m 0700 -o gdrive-stream-broker -g gdrive-stream-broker /var/lib/gdrive-stream-broker

umask 077
head -c 32 /dev/urandom | base64 > /tmp/token-key          # exactly 32 bytes, base64
openssl rand -hex 32 > /tmp/admin-token                   # 64 hex characters (>= 16)
printf '%s' '<client-secret-copied-from-google>' > /tmp/oauth-client-secret

sudo install -m 0440 -o root -g gdrive-stream-broker /tmp/token-key           /etc/gdrive-stream-broker/secrets/token-key
sudo install -m 0440 -o root -g gdrive-stream-broker /tmp/admin-token         /etc/gdrive-stream-broker/secrets/admin-token
sudo install -m 0440 -o root -g gdrive-stream-broker /tmp/oauth-client-secret /etc/gdrive-stream-broker/secrets/oauth-client-secret
shred -u /tmp/token-key /tmp/admin-token /tmp/oauth-client-secret
```

The master key must decode to exactly 32 bytes (padded or unpadded base64 is
accepted) and the admin token must be at least 16 characters; the broker refuses
to start otherwise. Secret file permissions are enforced too: a
`root:<service group>` file must be group-read-only for the service (`0440` or
`0640`), a file owned by the service account must be `0600`, and a
group-writable or other-accessible secret file is refused.

## 2. Write the non-secret runtime file

```bash
sudo install -m 0640 -o root -g gdrive-stream-broker \
  deploy/runtime.env.example /etc/gdrive-stream-broker/runtime.env
sudoedit /etc/gdrive-stream-broker/runtime.env   # replace every <value>
```

`GDRIVE_STREAM_ALLOWED_ROOT_NAME` is required and has no default: the broker
fails closed rather than sealing a folder nobody chose. Set it to the exact name
of your harmless test folder, and use the same name in the plugin setting
**Allowed Drive test root**.

`GDRIVE_STREAM_PAIR_TTL_MS` defaults to 5 minutes. If a human has to approve the
Google consent somewhere other than the device (for example the phone owner
approves on a laptop), raise it to `600000` and treat that as the time budget
for the whole round trip.

## 3. Build, then install the service

Build first: the unit starts `broker/dist/index.js`, and `broker/dist/` is not
committed, so a plain clone has nothing to run.

```bash
npm ci                 # exact dependency tree from the lockfile
npm run verify         # type checks, the full test suite, the plugin bundle
npm run broker:build   # produces broker/dist/index.js
```

Then install the prepared checkout:

```bash
sudo install -d -m 0755 /opt/gdrive-stream-broker/releases
sudo cp -a <reviewed-checkout> /opt/gdrive-stream-broker/releases/<version>
sudo ln -sfn /opt/gdrive-stream-broker/releases/<version> /opt/gdrive-stream-broker/current
sudo chown -R root:root /opt/gdrive-stream-broker

sudo install -m 0644 deploy/systemd/gdrive-stream-broker.system.service /etc/systemd/system/gdrive-stream-broker.service
sudo install -m 0644 deploy/apparmor/gdrive-stream-broker /etc/apparmor.d/gdrive-stream-broker
sudo apparmor_parser -r /etc/apparmor.d/gdrive-stream-broker
sudo systemctl daemon-reload
sudo systemctl enable --now gdrive-stream-broker.service
bash deploy/post-enable-acceptance.sh      # must print post_enable_acceptance=PASS
```

If an older `systemd --user` install exists on this host, retire it first with
the gate in [SELF_HOSTING.md](SELF_HOSTING.md) step 5 — a user unit accepts the
isolation directives without enforcing them.

## 4. Routing examples

Tailscale (the public path carries only the callback; the pairing API stays on
the tailnet):

```bash
# Public callback path. Needs root (or run `tailscale set --operator=$USER` once).
sudo tailscale funnel --bg --https=443 --set-path=/gdrive-stream-oauth http://127.0.0.1:34005
# Pairing/claim API: tailnet only, no funnel.
sudo tailscale serve  --bg --https=8445 --set-path=/gdrive-stream-api http://127.0.0.1:34006
sudo tailscale serve status      # confirm both mounts, then `tailscale funnel status`
```

The toggle syntax changed: on 1.102.x, `tailscale funnel 443 on` answers
`Error: the CLI for serve and funnel has changed.`, adding a trailing `on` after
flags answers `Error: invalid argument format`, and `off` is still parsed (it
removes an existing mount). Use the target-URL form above and check the flags on
the host you are configuring with `tailscale serve --help` / `funnel --help`.

nginx equivalent:

```nginx
server {
  listen 443 ssl;
  server_name <your-public-host>;
  location /gdrive-stream-oauth/ { proxy_pass http://127.0.0.1:34005/; }
  # Do NOT publish /gdrive-stream-api here: it belongs on the private network.
}
```

The plugin's **Broker base URL** is the private pairing mount, for example
`https://<your-private-host>:8445/gdrive-stream-api`.

## 5. Admin API (loopback only, bearer token)

Mint a single-use enrolment code pre-bound to one device fingerprint (the
64-character lowercase value the plugin shows):

```bash
sudo -u gdrive-stream-broker sh -c 'curl -s -X POST http://127.0.0.1:34004/admin/enrollment \
  -H "Authorization: Bearer $(cat /etc/gdrive-stream-broker/secrets/admin-token)" \
  -H "Content-Type: application/json" \
  -d "{\"deviceFingerprint\":\"<64-hex-fingerprint>\"}"'
# 201 {"code":"<one-time-code>","expiresAtMs":<epoch-ms>}

curl -s -H "Authorization: Bearer <admin-token>" http://127.0.0.1:34004/admin/enrollment
# 200 {"count":N,"used":N,"unused":N,"expiries":[...]}

curl -s -X POST http://127.0.0.1:34004/admin/revoke \
  -H "Authorization: Bearer <admin-token>" -H "Content-Type: application/json" \
  -d '{"pairId":"<pair-id>"}'
# 200 {"revoked":true}   (also clears the stored refresh token)
```

A malformed fingerprint is refused fail-closed:
`400 {"error":"invalid_device_fingerprint"}`, and a missing or wrong bearer
token answers `401 {"error":"unauthorized"}`.

## 6. Verify the deployment (expected non-secret outputs)

```bash
# 1. Only loopback listeners, one process, the service account.
sudo ss -ltnp | grep -E ':(34003|34004|34005|34006)\b'

# 2. The callback path answers publicly, and only that path.
curl -s -o /dev/null -w '%{http_code}\n' https://<your-public-host>/gdrive-stream-oauth/google/callback   # 400 with the gateway's HTML failure page
curl -s -o /dev/null -w '%{http_code}\n' https://<your-public-host>/gdrive-stream-oauth/other           # 404

# 3. The pairing mount answers on the private network and refuses junk.
curl -s -X POST https://<your-private-host>:8445/gdrive-stream-api/oauth/pair \
  -H 'Content-Type: application/json' -d '{}'    # 400, a broker JSON error — proves reachability

# 4. The admin port is unreachable from anywhere else.
curl -s -o /dev/null -w '%{http_code}\n' http://<your-public-host>:34004/admin/enrollment   # connection refused / timeout
```

Then complete the device flow and record the results in
[DEPLOYMENT_EVIDENCE.md](DEPLOYMENT_EVIDENCE.md): granted scope exactly
`drive.readonly`, metadata listing, metadata-only search, one explicit download,
cache no-overwrite, and no create/rename/move/trash/delete request anywhere.

## 7. Logout, revocation and uninstall

- **Revoke a device**: `POST /admin/revoke` with its `pairId`. Revocation also
  clears the stored refresh token, so the next enrolment needs a fresh Google
  consent round trip.
- **Rotate `admin-token` or `oauth-client-secret`**: install the new file, then
  `sudo systemctl restart gdrive-stream-broker`. Existing device enrolments keep
  working, because neither value is used to seal the state files.
- **Rotate `token-key`** (the master key that seals the state files). The stored
  records are AES-256-GCM sealed with it, so a new key cannot read the old
  files: the broker fails while loading its state and `Restart=on-failure` loops.
  Archive the state deliberately, in this order:

  ```bash
  sudo systemctl stop gdrive-stream-broker
  sudo mv /var/lib/gdrive-stream-broker /var/lib/gdrive-stream-broker.pre-rotation.$(date +%Y%m%d%H%M%S)
  sudo install -d -m 0700 -o gdrive-stream-broker -g gdrive-stream-broker /var/lib/gdrive-stream-broker
  sudo install -m 0440 -o root -g gdrive-stream-broker <new-token-key-file> /etc/gdrive-stream-broker/secrets/token-key
  sudo systemctl start gdrive-stream-broker
  bash deploy/post-enable-acceptance.sh      # post_enable_acceptance=PASS
  ```

  Consequences: every device enrols again with a fresh Google consent, the
  archive keeps the old sealed records readable only with the old key, and the
  operator should revoke the superseded Drive grant in the Google account. Keep
  the archive only as long as you need the audit trail, then destroy it.
- **Suspect compromise**: revoke the Google grant in the operator account,
  revoke the device, stop the service, preserve sanitised logs, then rotate the
  client secret, admin token and master key.
- **Uninstall**: stop and disable the service, remove the routing mounts, then
  remove the release, configuration and state directories — never delete
  production data as part of a rollback.

## 8. Identity scan before every public push, tag or release

```bash
IDENTITY_DENYLIST=/secure/path/identity-denylist.txt python3 scripts/identity_scan.py .
# identity_scan=PASS_WITH_DECLARED_EXCEPTIONS
bash scripts/identity-scan-selftest.sh          # 18 adversarial scenarios
# identity_scan_selftest=PASS
```

**Verdicts and exit status.** `PASS` (nothing found, nothing declared, nothing
used) and `PASS_WITH_DECLARED_EXCEPTIONS` exit 0; `FAIL` exits 1; a configuration
error exits 2. The verdict is never a plain `PASS` while a declared exception is
in play, so a green run cannot hide one.

**A deny-list is required and must be usable.** It lives outside the tree (a
committed deny-list leaks what it lists) and must contain at least one valid
regex; empty, comment-only or invalid deny-lists are configuration errors, not
passes. `IDENTITY_ALLOW_NO_DENYLIST=1` allows a smoke run that reports itself as
non-authoritative — that is what CI runs, because CI has no operator deny-list.

**Five surfaces.** Working-tree contents **and file names**, every reachable
blob and path, every commit and tag message, the Git identity metadata, and the
release artefacts.

**How matching works** (the reason it is not a shell script): every candidate
text is matched against every pattern with full spans, and each match is
classified by whether its *whole* span is covered by a declared exemption —
fully covered is `EXEMPT`, partially covered is a hit, uncovered is a hit.
Nothing is truncated before analysis. That closes truncation, ordering,
partial-overlap and regex-delimiter bypasses at once.

**Declared exemptions** (`scripts/identity-exemptions.txt`, `regex ::
justification`) are printed as `EXEMPT ... <= <why>`; a line without a
justification fails the run. They never silence the identity metadata: a match
there is reported as `KNOWN-IDENTITY-EXCEPTION`, counted, and forces the verdict
to `PASS_WITH_DECLARED_EXCEPTIONS`.

**Not scanned, by scope decision:** `.git` and `node_modules` (neither is
distributed, and content that reaches a release is caught by the artefact
surface). No file inside the tree is excluded by path: a forbidden identifier
planted in any file, any file name or any historical blob is reported.

**Strict mode** `IDENTITY_REQUIRE_NO_EXEMPTIONS=1` fails when an exemption is
used, when one is declared, or when a known identity exception exists, and prints
each reason. For this repository it fails in every configuration, which is the
honest measure of the declared owner-account exception.

**The gate is itself tested:** 18 scenarios, each checking the **exit status**
and the expected output, because a gate that prints FAIL and returns success is
exactly the failure a text-only test misses. Scenarios cover missing, empty,
comment-only and invalid deny-lists; identifiers planted in another file, in a
file name, and under the tool's own basename elsewhere; co-location and partial
overlap with an exempted value; a forbidden value 400 characters into a line; an
exemption pattern containing a path separator; a leak present in history but
removed from the tree; identity metadata outside the policy; metadata matching a
declared exemption; and the smoke-mode flag.
