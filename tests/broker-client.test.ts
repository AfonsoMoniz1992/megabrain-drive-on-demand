import { afterEach, describe, expect, it, vi } from "vitest";
import { BrokerClient, BrokerError, type BrokerRequest, type BrokerResponse } from "../src/auth/broker-client";

const BASE_URL = "https://broker.example.test/gdrive-stream-oauth";

interface Recorded {
  calls: BrokerRequest[];
  transport: (request: BrokerRequest) => Promise<BrokerResponse>;
}

function transportReturning(responses: Array<BrokerResponse | (() => BrokerResponse)>): Recorded {
  const calls: BrokerRequest[] = [];
  const queue = [...responses];
  return {
    calls,
    async transport(request) {
      calls.push(request);
      const next = queue.shift();
      if (!next) throw new Error("unexpected broker call");
      return typeof next === "function" ? next() : next;
    }
  };
}

const pairBody = {
  enrollmentCode: "ENROLL-1234",
  devicePublicKeyPem: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
  deviceEncryptionPublicKeyPem: "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----"
};

const pairResponse = {
  status: 201,
  json: {
    pairId: "a".repeat(64),
    oauthState: "s".repeat(43),
    proofMessage: "gdrive-stream-pair-proof",
    expiresAtMs: 1_700_000_000_000,
    authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth?client_id=test-client&state=abc"
  }
};

const sealedEnvelope = { v: 1, epk: "e".repeat(43), salt: "s".repeat(22), nonce: "n".repeat(16), ct: "c".repeat(32) };

afterEach(() => {
  vi.restoreAllMocks();
});

describe("broker client", () => {
  it("posts the pairing request with device public keys only", async () => {
    const fake = transportReturning([pairResponse]);
    const client = new BrokerClient({ baseUrl: BASE_URL, request: fake.transport });
    const result = await client.pair(pairBody);

    expect(result).toEqual(pairResponse.json);
    expect(fake.calls).toHaveLength(1);
    expect(fake.calls[0].url).toBe(`${BASE_URL}/oauth/pair`);
    expect(fake.calls[0].method).toBe("POST");
    expect(fake.calls[0].headers?.["Content-Type"]).toContain("application/json");
    const sent = JSON.parse(String(fake.calls[0].body));
    expect(sent).toEqual(pairBody);
    expect(Object.keys(sent).sort()).toEqual(["deviceEncryptionPublicKeyPem", "devicePublicKeyPem", "enrollmentCode"]);
  });

  it("maps an invalid or reused enrollment code to a typed error", async () => {
    const enrollmentRequired: BrokerResponse = { status: 403, json: { error: "enrollment_required" } };
    const client = new BrokerClient({ baseUrl: BASE_URL, request: transportReturning([enrollmentRequired, enrollmentRequired]).transport });
    await expect(client.pair(pairBody)).rejects.toBeInstanceOf(BrokerError);
    await expect(client.pair(pairBody)).rejects.toMatchObject({ code: "enrollment_required", status: 403 });
  });

  it("wraps a transport failure as a typed transport error", async () => {
    const client = new BrokerClient({ baseUrl: BASE_URL, request: async () => { throw new Error("socket hang up"); } });
    await expect(client.nonce({ pairId: "a".repeat(64) })).rejects.toMatchObject({ code: "transport" });
  });

  it("maps claim and lease statuses to typed errors", async () => {
    const client = (responses: Array<BrokerResponse>) => new BrokerClient({ baseUrl: BASE_URL, request: transportReturning(responses).transport });
    await expect(client([{ status: 409, json: { error: "not_authorized_yet" } }]).claim({ pairId: "a".repeat(64), proof: "p" }))
      .rejects.toMatchObject({ code: "not_authorized_yet", status: 409 });
    await expect(client([{ status: 403, json: { error: "revoked" } }]).lease({ pairId: "a".repeat(64), nonce: "n", proof: "p" }))
      .rejects.toMatchObject({ code: "revoked", status: 403 });
    await expect(client([{ status: 410, json: { error: "expired" } }]).claim({ pairId: "a".repeat(64), proof: "p" }))
      .rejects.toMatchObject({ code: "expired", status: 410 });
    await expect(client([{ status: 500, json: { error: "ya29.super-secret-token" } }]).nonce({ pairId: "a".repeat(64) }))
      .rejects.toMatchObject({ code: "unexpected_status", status: 500 });
  });

  it("normalizes a JSON-string sealed lease from either response shape", async () => {
    const client = new BrokerClient({
      baseUrl: BASE_URL,
      request: transportReturning([
        { status: 200, json: { sealedLease: JSON.stringify(sealedEnvelope), expiresAtMs: 1_700_000_000_000 } },
        { status: 200, json: { sealedLease: sealedEnvelope, expiresAtMs: 1_700_000_000_000 } }
      ]).transport
    });
    const claimed = await client.claim({ pairId: "a".repeat(64), proof: "proof" });
    const leased = await client.lease({ pairId: "a".repeat(64), nonce: "nonce-value", proof: "proof" });
    expect(claimed.sealedLease).toEqual(sealedEnvelope);
    expect(claimed.expiresAtMs).toBe(1_700_000_000_000);
    expect(leased.sealedLease).toEqual(sealedEnvelope);
  });

  it("returns the single-use nonce and rejects malformed responses", async () => {
    const client = new BrokerClient({ baseUrl: BASE_URL, request: transportReturning([{ status: 200, json: { nonce: "n".repeat(32), expiresAtMs: 42 } }, { status: 200, json: { expiresAtMs: 42 } }]).transport });
    await expect(client.nonce({ pairId: "a".repeat(64) })).resolves.toEqual({ nonce: "n".repeat(32), expiresAtMs: 42 });
    await expect(client.nonce({ pairId: "a".repeat(64) })).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("refuses a non-HTTPS broker origin and an authorization URL carrying token material", async () => {
    expect(() => new BrokerClient({ baseUrl: "http://broker.example", request: transportReturning([]).transport })).toThrow(/https/i);
    expect(() => new BrokerClient({ baseUrl: "https://host.example/gdrive-stream-oauth/../evil", request: transportReturning([]).transport })).toThrow(/traversal/i);
    expect(() => new BrokerClient({ baseUrl: "https://host.example/gdrive-stream-oauth?token=x", request: transportReturning([]).transport })).toThrow(/query/i);
    expect(new BrokerClient({ baseUrl: `${BASE_URL}/`, request: transportReturning([]).transport }).baseUrl).toBe(BASE_URL);
    const client = new BrokerClient({
      baseUrl: BASE_URL,
      request: transportReturning([{ status: 201, json: { ...pairResponse.json, authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth?access_token=ya29.nope" } }]).transport
    });
    await expect(client.pair(pairBody)).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("never logs pairing, nonce or lease payloads", async () => {
    const spies = (["log", "info", "warn", "error", "debug"] as const).map((level) => vi.spyOn(console, level).mockImplementation(() => undefined));
    const client = new BrokerClient({
      baseUrl: BASE_URL,
      request: transportReturning([
        pairResponse,
        { status: 200, json: { nonce: "n".repeat(32), expiresAtMs: 42 } },
        { status: 200, json: { sealedLease: sealedEnvelope, expiresAtMs: 1 } },
        { status: 403, json: { error: "revoked" } }
      ]).transport
    });
    await client.pair(pairBody);
    await client.nonce({ pairId: "a".repeat(64) });
    await client.lease({ pairId: "a".repeat(64), nonce: "n", proof: "p" });
    await client.claim({ pairId: "a".repeat(64), proof: "p" }).catch(() => undefined);
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
  });

  it("does not place response bodies inside error messages", async () => {
    const client = new BrokerClient({ baseUrl: BASE_URL, request: transportReturning([{ status: 500, json: { error: "ya29.super-secret-token" } }]).transport });
    try {
      await client.nonce({ pairId: "a".repeat(64) });
      throw new Error("expected rejection");
    } catch (error) {
      expect(error).toBeInstanceOf(BrokerError);
      expect(String(error)).not.toContain("ya29");
      expect(String((error as BrokerError).message)).not.toContain("secret");
    }
  });
});
