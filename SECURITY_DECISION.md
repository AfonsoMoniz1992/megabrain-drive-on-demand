# Security decision — mobile Drive boundary

**Decision:** `direct-lease` for the self-hosted mobile beta.

## Meaning

- The operator-hosted broker owns the Google refresh token and the fixed OAuth callback.
- A paired mobile device receives only a short-lived, device-key-authenticated **read-only access-token lease**.
- The plugin calls approved Google Drive read endpoints directly; the broker does not proxy file bytes or index content.
- The plugin restricts its UI/index to the single harmless test root the operator configures (**Allowed Drive test root**, matching the broker's `GDRIVE_STREAM_ALLOWED_ROOT_NAME`), but this is **not** a Google permission boundary: the chosen Google `drive.readonly` grant can technically access more of the selected account's Drive.

## Risk acceptance and safeguards

This is accepted only for a private, named-user beta against harmless test data.

- No connection to a production knowledge tree while the beta is unvalidated.
- No public BRAT release while the Google OAuth client remains in testing mode.
- No refresh token or client secret in the mobile plugin.
- Device-bound leases are short-lived, revocable and never logged.
- The plugin refuses a lease sealed to any root other than its configured one, so a broker/plugin root mismatch fails closed instead of browsing the wrong folder.
- No Drive mutation endpoints/UI are compiled into the beta.
- A strict folder-boundary product later requires the alternative allowlisted-proxy design.
