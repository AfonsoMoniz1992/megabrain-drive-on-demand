import { describe, expect, it } from "vitest";
import { BrokerClient, type BrokerRequest, type BrokerResponse } from "../src/auth/broker-client";
import { generateDeviceIdentity, sealLeaseEnvelope, type LeasePayload } from "../src/auth/device-identity";
import { LeaseManager } from "../src/auth/lease-manager";
import { DriveRootScope, DRIVE_FOLDER_MIME } from "../src/drive/root-scope";
import { DEFAULT_SETTINGS, normalizeAllowedRootName } from "../src/settings";
import { createBrokerServer } from "../broker/src/server";

/**
 * The broker seals the operator-configured allowed root into every lease, and the
 * plugin refuses a lease scoped to a different root. These two sides must agree on
 * one contract, otherwise a self-hosted operator whose test root is not named
 * `example-test-root` can pair successfully but never obtain a usable lease.
 */

const BASE_URL = "https://broker.example.test/gdrive-stream-oauth";
const OPERATOR_ROOT = "operator-test-root";

function leaseHarness(options: { sealedRootName: string; configuredRootName: string }) {
  const identity = generateDeviceIdentity();
  const nowMs = 1_000_000;
  const payload: LeasePayload = {
    accessToken: "ya29.contract-test",
    expiresAtMs: 600_000,
    scope: "drive.readonly",
    allowedRootName: options.sealedRootName
  };
  const transport = async (request: BrokerRequest): Promise<BrokerResponse> => {
    if (request.url.endsWith("/oauth/pair")) {
      return {
        status: 201,
        json: {
          pairId: "b".repeat(64),
          oauthState: "s".repeat(43),
          proofMessage: "proof",
          expiresAtMs: nowMs + 600_000,
          authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth?client_id=public"
        }
      };
    }
    if (request.url.endsWith("/oauth/claim")) {
      // The sealed expiry is an absolute instant derived from the test clock, so
      // the resulting lease is genuinely valid rather than merely present.
      const expiresAtMs = nowMs + payload.expiresAtMs;
      return { status: 200, json: { sealedLease: sealLeaseEnvelope(identity.x25519PublicKey, { ...payload, expiresAtMs }), expiresAtMs } };
    }
    throw new Error(`unexpected ${request.url}`);
  };
  return new LeaseManager({
    broker: new BrokerClient({ baseUrl: BASE_URL, request: transport }),
    identity,
    openAuthorizationUrl: () => undefined,
    rootFolderName: options.configuredRootName,
    now: () => nowMs,
    sleep: async () => undefined
  });
}

describe("operator-configurable root contract", () => {
  it("enrols with a genuinely usable lease when the sealed root matches the configured root", async () => {
    const manager = leaseHarness({ sealedRootName: OPERATOR_ROOT, configuredRootName: OPERATOR_ROOT });
    const state = await manager.enroll("ENROLL-TEST-CODE");
    expect(state.allowedRootName).toBe(OPERATOR_ROOT);
    // `enrolled` only means a lease object exists; the root contract requires a
    // lease that is actually usable for a non-default root.
    expect(manager.hasValidLease()).toBe(true);
    await expect(manager.getValidAccessToken()).resolves.toBe("ya29.contract-test");
  });

  it("rejects a lease sealed to a different root than the plugin is configured for", async () => {
    const manager = leaseHarness({ sealedRootName: OPERATOR_ROOT, configuredRootName: "example-test-root" });
    await expect(manager.enroll("ENROLL-TEST-CODE")).rejects.toThrow(/not scoped to the example-test-root root folder/i);
    expect(manager.enrolled).toBe(false);
  });

  it("resolves and confines the configured root instead of a hard-coded default", async () => {
    const names: string[] = [];
    const scope = new DriveRootScope({
      listFoldersByName: async (name: string) => {
        names.push(name);
        return [{ id: "rootid", name, mimeType: DRIVE_FOLDER_MIME }];
      }
    }, OPERATOR_ROOT);
    const rootId = await scope.resolveRootId();
    expect(names).toEqual([OPERATOR_ROOT]);
    expect(scope.rootFolderName).toBe(OPERATOR_ROOT);
    expect(scope.isWithinRoot(rootId)).toBe(true);
    expect(scope.isWithinRoot("unrelated-id")).toBe(false);
  });

  it("requires the operator to name their own root instead of shipping a personal default", () => {
    expect(DEFAULT_SETTINGS.allowedRootName).toBe("");
    expect(normalizeAllowedRootName(OPERATOR_ROOT)).toBe(OPERATOR_ROOT);
    expect(normalizeAllowedRootName("  spaced-root  ")).toBe("spaced-root");
    expect(normalizeAllowedRootName("")).toBe("");
    // A path or control character can never become the allowed root.
    expect(normalizeAllowedRootName("production/root")).toBe("");
    expect(normalizeAllowedRootName("..")).toBe("");
    expect(normalizeAllowedRootName("a\\b")).toBe("");
  });

  it("fails closed at broker construction for a path-like, dot-segment or empty root name", () => {
    // The broker validator must reject every value the plugin would normalise
    // away, otherwise it would seal a root the plugin can never match.
    for (const rejected of ["production/root", "a\\b", "", ".", "..", "  padded  ", "\u0000bad"]) {
      expect(() => createBrokerServer({ allowedRootName: rejected })).toThrow(/invalid allowed root folder name/i);
    }
    expect(() => createBrokerServer({ allowedRootName: OPERATOR_ROOT })).not.toThrow();
    expect(() => createBrokerServer({ allowedRootName: "example-test-root" })).not.toThrow();
  });
});
