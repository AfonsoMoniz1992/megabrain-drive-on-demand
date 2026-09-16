# Delivery status

This is the public delivery contract. **Implemented** means the reviewed source exists; it does not mean your self-hosted deployment, Google OAuth configuration, or physical device has been validated.

| Capability | Source and automated checks | Operator evidence required |
|---|---|---|
| Read-only metadata browser | Implemented and tested | Test only against a harmless dedicated root |
| Explicit single-file cache download | Implemented and tested | Confirm no-overwrite behaviour on each device |
| Mobile pairing and encrypted leases | Implemented and tested | Configure and exercise an operator-owned OAuth client |
| Configured-root contract | Broker requires an explicit root; plugin verifies the sealed root | Use the same root value on both sides |
| System service and mount isolation | Versioned template and tests | Prove production and test Drive paths are blocked from the broker PID namespace |
| AppArmor defence in depth | Versioned template and tests | Verify an enforcing label on the running broker process |
| Post-enable acceptance gate | Versioned, tested script | Run it after every deployment or service configuration change |
| Google OAuth consent | Code-level contracts only | Complete real consent against harmless test data |
| BRAT installation/update | Public v1.0.5 beta artefact; no broker or OAuth client is included | Install only in a disposable/test vault; copy the full canonical device fingerprint and configure an operator-owned broker URL and test-root name before enrolling a device.
| iOS validation | Partially observed in the reference deployment: consent completed, sealed-root metadata listing and one on-demand download/opened note. Restart, offline/reconnect, cache cleanup and logout/re-enrol not recorded. | OAuth, restart, offline/reconnect, cache, and logout/re-enrol |
| Android validation | Not yet recorded | OAuth, restart, offline/reconnect, cache, and logout/re-enrol |

## Release and usage decision

**Public self-hosted beta: BRAT distributes only the plugin artefacts. It is not production-ready and includes no operated broker, OAuth client, callback host, Google account, or Drive data.**

Before a production Drive tree is ever connected, an operator must:

1. Run `npm run verify` from the intended release source and verify the published asset checksums.
2. Deploy the broker under a dedicated system account with root-controlled configuration, effective mount isolation, and AppArmor enforcing; negatively test both production and test Drive paths from the broker PID namespace.
3. Exercise OAuth only against harmless test data; record redirect URI, exact scope, and audience without credentials or tokens.
4. Confirm root guard, metadata listing, selected-file download, cache no-overwrite behaviour, and logout against the test root.
5. Pass iOS and Android OAuth, restart, offline/reconnect, cache cleanup, Unicode/deep-path, and revoke/re-enrol tests.
6. Have an independent reviewer accept the recorded evidence and release notes.
7. Continue to satisfy the legal/provenance conditions in [FORK_PROVENANCE.md](FORK_PROVENANCE.md).

A passing unit suite is not a substitute for these deployment and physical-device gates.
