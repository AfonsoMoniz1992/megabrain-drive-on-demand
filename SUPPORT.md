# Support

## Supported scope

Current support covers source builds and private self-hosted testing of the read-only mobile flow against a harmless, operator-owned Drive test root. It does not cover production knowledge-tree access, write/sync behavior, Community Directory submission, or any claim of iOS/Android compatibility until the gates in [STATUS.md](STATUS.md) are complete.

## Before opening an issue

1. Check [STATUS.md](STATUS.md), [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md) and [SECURITY.md](SECURITY.md).
2. Reproduce against a harmless test root, never a production Drive tree.
3. Provide version, OS/Obsidian version, non-secret deployment topology, expected/actual behavior and sanitized logs.
4. Do **not** include vault contents, Drive URLs, OAuth codes, tokens, client secrets, enrollment codes, device private keys or screenshots containing them.

Security-sensitive reports must follow the private reporting route in [SECURITY.md](SECURITY.md), not a public issue.