# Operator runbook (copy-paste)

Command-first companion to [SELF_HOSTING.md](SELF_HOSTING.md). Replace every
`<angle-bracketed>` value. Nothing here contains an operator hostname, account,
project ID, client ID, secret or Drive identifier.

## 0. What you need

- A host you control with systemd and AppArmor in enforcing mode.
- **Node.js 22** (the version CI builds and tests with): `node --version`.
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
head -c 32 /dev/urandom | xxd -p -c 64 > /tmp/admin-token  # at least 16 characters
printf '%s' '<client-secret-copied-from-google>' > /tmp/oauth-client-secret

sudo install -m 0440 -o root -g gdrive-stream-broker /tmp/token-key           /etc/gdrive-stream-broker/secrets/token-key
sudo install -m 0440 -o root -g gdrive-stream-broker /tmp/admin-token         /etc/gdrive-stream-broker/secrets/admin-token
sudo install -m 0440 -o root -g gdrive-stream-broker /tmp/oauth-client-secret /etc/gdrive-stream-broker/secrets/oauth-client-secret
shred -u /tmp/token-key /tmp/admin-token /tmp/oauth-client-secret
```

The master key must decode to exactly 32 bytes (padded or unpadded base64 is
accepted) and the admin token must be at least 16 characters; the broker refuses
to start otherwise. Secret files must be `root:<service group>` mode `0440`.

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

## 3. Install the service

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
tailscale serve --bg --https=443  --set-path=/gdrive-stream-oauth http://127.0.0.1:34005
tailscale funnel --bg --https=443  --set-path=/gdrive-stream-oauth on   # only if the callback must be public
tailscale serve --bg --https=8445 --set-path=/gdrive-stream-api   http://127.0.0.1:34006
```

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
curl -s -o /dev/null -w '%{http_code}\n' https://<your-public-host>/gdrive-stream-oauth/google/callback   # 400 (no code) rather than a page
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
- **Rotate a secret**: replace the file, then `systemctl restart
  gdrive-stream-broker`. Rotating `token-key` invalidates the encrypted state
  files; re-enrol the devices afterwards.
- **Suspect compromise**: revoke the Google grant in the operator account,
  revoke the device, stop the service, preserve sanitised logs, then rotate the
  client secret, admin token and master key.
- **Uninstall**: stop and disable the service, remove the routing mounts, then
  remove the release, configuration and state directories — never delete
  production data as part of a rollback.
