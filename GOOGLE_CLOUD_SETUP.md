# Google Cloud and OAuth setup

This is a generic self-hosted setup guide. It intentionally contains no operator hostname, account, project ID, client ID or secret.

## Required project settings

1. Create an operator-owned Google Cloud project and enable the Google Drive API.
2. Configure an OAuth consent screen limited to named beta/test users while testing.
3. Create a **Web application** OAuth client for the self-hosted broker callback.
4. Register exactly: `https://<your-public-host>/gdrive-stream-oauth/google/callback`.
5. Configure exactly: `https://www.googleapis.com/auth/drive.readonly`.

The client ID is public configuration; the client secret belongs only on the broker in a protected secret file. Never embed either in the mobile plugin.

## Verification before consent

- Verify Drive API is enabled and audience/users are restricted appropriately.
- Compare the redirect URI byte-for-byte between Google Cloud and broker configuration.
- Verify the public callback and private network/private pairing routes separately.
- After consent, verify granted scope is exactly `drive.readonly`.
- Use only a harmless test root. Do not authorize a production knowledge tree based on a successful unit test.

See [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md) and [docs/DEPLOYMENT_EVIDENCE.md](docs/DEPLOYMENT_EVIDENCE.md).
