import { describe, expect, it } from "vitest";
import {
  GoogleOAuthClient,
  GoogleOAuthScopeError,
  GoogleOAuthTokenError,
  type OAuthTokenTransport,
  type OAuthTransportRequest
} from "../broker/src/google-oauth-client";

const scope = "https://www.googleapis.com/auth/drive.readonly";
const clientSecret = "test-client-secret-must-not-leak";
const refreshToken = "1//0g-refresh-token-must-not-leak";
const accessToken = "ya29.test-access-token-must-not-leak";

function client(): GoogleOAuthClient {
  return new GoogleOAuthClient({
    googleClientId: "test-client.apps.googleusercontent.com",
    googleCallbackUri: "https://broker.example.test/oauth/google/callback",
    googleDriveScope: scope
  });
}

function recorder(body: string, status = 200): { requests: OAuthTransportRequest[]; transport: OAuthTokenTransport } {
  const requests: OAuthTransportRequest[] = [];
  return {
    requests,
    transport: async (request) => {
      requests.push(request);
      return { status, body };
    }
  };
}

function refreshBody(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({ access_token: accessToken, token_type: "Bearer", expires_in: 3_600, scope, ...overrides });
}

async function capture(action: () => Promise<unknown>): Promise<Error> {
  try {
    await action();
  } catch (error) {
    return error as Error;
  }
  throw new Error("expected the call to fail closed, but it resolved");
}

describe("Google OAuth refresh-token grant", () => {
  it("POSTs a form-encoded refresh_token grant to the token endpoint", async () => {
    const { requests, transport } = recorder(refreshBody());

    const tokens = await client().refreshAccessToken({ refreshToken, clientSecret, transport });

    expect(requests).toHaveLength(1);
    const [request] = requests;
    expect(request.url).toBe("https://oauth2.googleapis.com/token");
    expect(request.method).toBe("POST");
    expect(request.headers["content-type"]).toBe("application/x-www-form-urlencoded");
    expect(Object.fromEntries(new URLSearchParams(request.body))).toEqual({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: "test-client.apps.googleusercontent.com",
      client_secret: clientSecret
    });
    expect(tokens).toEqual({ accessToken, tokenType: "Bearer", expiresIn: 3_600, scope });
  });

  it("accepts a response without expires_in", async () => {
    const { transport } = recorder(refreshBody({ expires_in: undefined }));
    const tokens = await client().refreshAccessToken({ refreshToken, clientSecret, transport });
    expect(tokens).toEqual({ accessToken, tokenType: "Bearer", scope });
    expect(tokens).not.toHaveProperty("expiresIn");
  });

  it("fails closed with a typed error on a non-2xx response without leaking provider data", async () => {
    const { transport } = recorder(JSON.stringify({ error: "invalid_grant", error_description: "sensitive" }), 400);
    const failure = await capture(() => client().refreshAccessToken({ refreshToken, clientSecret, transport }));
    expect(failure).toBeInstanceOf(GoogleOAuthTokenError);
    expect((failure as GoogleOAuthTokenError).code).toBe("token_endpoint_error");
    expect(failure.message).not.toContain("invalid_grant");
    expect(failure.message).not.toContain("sensitive");
    expect(failure.message).not.toContain(refreshToken);
    expect(failure.message).not.toContain(clientSecret);
  });

  it("fails closed on a malformed body", async () => {
    for (const body of ["not json", JSON.stringify({ token_type: "Bearer", scope }), JSON.stringify({ access_token: "" })]) {
      const { transport } = recorder(body);
      const failure = await capture(() => client().refreshAccessToken({ refreshToken, clientSecret, transport }));
      expect(failure).toBeInstanceOf(GoogleOAuthTokenError);
      expect((failure as GoogleOAuthTokenError).code).toBe("malformed_response");
    }
  });

  it("fails closed when the granted scope is broader than the allowed set", async () => {
    const { transport } = recorder(refreshBody({ scope: `${scope} https://www.googleapis.com/auth/drive` }));
    const failure = await capture(() => client().refreshAccessToken({ refreshToken, clientSecret, transport }));
    expect(failure).toBeInstanceOf(GoogleOAuthScopeError);
    expect((failure as GoogleOAuthScopeError).code).toBe("unexpected_scope");
  });

  it("fails closed when the granted scope omits drive.readonly", async () => {
    const { transport } = recorder(refreshBody({ scope: "https://www.googleapis.com/auth/drive.metadata.readonly" }));
    const failure = await capture(() => client().refreshAccessToken({ refreshToken, clientSecret, transport }));
    expect(failure).toBeInstanceOf(GoogleOAuthScopeError);
    expect((failure as GoogleOAuthScopeError).code).toBe("required_scope_missing");
  });
});
