# Contributing

Thank you for improving GDrive Streaming.

- Read [FORK_PROVENANCE.md](FORK_PROVENANCE.md), [SECURITY.md](SECURITY.md) and [STATUS.md](STATUS.md) before proposing a feature.
- Keep the first release read-only. Do not introduce Drive mutation calls, hidden sync, token persistence or undocumented telemetry.
- Use test-driven development for code changes: add a failing behavioral test, make it pass, then run `npm run verify`.
- Keep operator-specific hostnames, OAuth client IDs, paths, secret names and credentials out of public source and documentation.
- Document any new network destination, local persistence field, cache behavior or permission requirement.
- Do not submit upstream-derived work to an Obsidian directory until the provenance gate is met.

Pull requests should describe the user-visible change, security impact, tests run, and any remaining deployment/device gate.