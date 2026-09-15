import { describe, expect, it } from "vitest";
import {
  GoogleOAuthClient,
  GoogleOAuthScopeError,
  GoogleOAuthTokenError,
  validateGrantedScope,
  type OAuthTokenTransport,
  type OAuthTransportRequest
} from "../broker/src/google-oauth-client";

const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const state = "opaque-state-value";
const scope = "https://www.googleapis.com/auth/drive.readonly";
const clientSecret = "test-client-secret-must-not-leak";
const code = "test-authorization-code-must-not-leak";

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

function tokenBody(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    access_token: "ya29.test-access-token",
    token_type: "Bearer",
    refresh_token: "1//0g.test-refresh-token",
    expires_in: 3600,
    scope,
    ...overrides
  });
}

async function capture(action: () => Promise<unknown>): Promise<Error> {
  try {
    await action();
  } catch (error) {
    return error as Error;
  }
  throw new Error("expected the call to fail closed, but it resolved");
}

function captureSync(action: () => unknown): Error {
  try {
    action();
  } catch (error) {
    return error as Error;
  }
  throw new Error("expected the call to fail closed, but it returned");
}

describe("Google OAuth authorization client", () => {
  it("builds a Drive readonly PKCE authorization URL without private pairing material", () => {
    const authorizationUrl = client().createAuthorizationUrl({ oauthState: state, pkceVerifier: verifier });
    const url = new URL(authorizationUrl);

    expect(`${url.origin}${url.pathname}`).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(Object.fromEntries(url.searchParams)).toEqual({
      client_id: "test-client.apps.googleusercontent.com",
      redirect_uri: "https://broker.example.test/oauth/google/callback",
      response_type: "code",
      scope,
      state,
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "S256",
      access_type: "offline",
      prompt: "consent"
    });
    expect(authorizationUrl).not.toContain(verifier);
    expect(authorizationUrl).not.toContain("pairId");
    expect(authorizationUrl).not.toContain("client_secret");
    expect(authorizationUrl).not.toContain("token");
  });
});

describe("Google OAuth authorization-code exchange", () => {
  it("POSTs the form-encoded grant with the PKCE verifier and exact redirect URI", async () => {
    const { requests, transport } = recorder(tokenBody());

    const tokens = await client().exchangeAuthorizationCode({ code, codeVerifier: verifier, clientSecret, transport });

    expect(requests).toHaveLength(1);
    const [request] = requests;
    expect(request.url).toBe("https://oauth2.googleapis.com/token");
    expect(request.method).toBe("POST");
    expect(request.headers["content-type"]).toBe("application/x-www-form-urlencoded");
    expect(Object.fromEntries(new URLSearchParams(request.body))).toEqual({
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      client_id: "test-client.apps.googleusercontent.com",
      client_secret: clientSecret,
      redirect_uri: "https://broker.example.test/oauth/google/callback"
    });
    expect(tokens).toEqual({
      accessToken: "ya29.test-access-token",
      tokenType: "Bearer",
      refreshToken: "1//0g.test-refresh-token",
      expiresIn: 3600,
      scope
    });
  });

  it("accepts a response that omits the optional refresh token and expiry", async () => {
    const { transport } = recorder(JSON.stringify({ access_token: "ya29.test-access-token", token_type: "Bearer", scope }));

    const tokens = await client().exchangeAuthorizationCode({ code, codeVerifier: verifier, clientSecret, transport });

    expect(tokens).toEqual({ accessToken: "ya29.test-access-token", tokenType: "Bearer", scope });
    expect(tokens).not.toHaveProperty("refreshToken");
  });

  it("fails closed with a typed error on a non-2xx token response without leaking provider data", async () => {
    const providerError = JSON.stringify({ error: "invalid_grant", error_description: "sensitive-provider-detail" });
    const { transport } = recorder(providerError, 400);

    const failure = await capture(() => client().exchangeAuthorizationCode({ code, codeVerifier: verifier, clientSecret, transport }));

    expect(failure).toBeInstanceOf(GoogleOAuthTokenError);
    expect((failure as GoogleOAuthTokenError).code).toBe("token_endpoint_error");
    expect(failure.message).not.toContain("invalid_grant");
    expect(failure.message).not.toContain("sensitive-provider-detail");
    expect(failure.message).not.toContain(code);
    expect(failure.message).not.toContain(verifier);
    expect(failure.message).not.toContain(clientSecret);
  });

  it("fails closed with a typed error on a malformed token body", async () => {
    for (const body of [
      "not json",
      JSON.stringify({ token_type: "Bearer", scope }),
      JSON.stringify({ access_token: "", token_type: "Bearer", scope }),
      JSON.stringify({ access_token: "ya29.test-access-token", scope }),
      JSON.stringify({ access_token: "ya29.test-access-token", token_type: "Bearer" }),
      JSON.stringify({ access_token: "ya29.test-access-token", token_type: "Bearer", refresh_token: 5, scope }),
      JSON.stringify({ access_token: "ya29.test-access-token", token_type: "Bearer", expires_in: "3600", scope })
    ]) {
      const { transport } = recorder(body);
      const failure = await capture(() =>
        client().exchangeAuthorizationCode({ code, codeVerifier: verifier, clientSecret, transport })
      );
      expect(failure).toBeInstanceOf(GoogleOAuthTokenError);
      expect((failure as GoogleOAuthTokenError).code).toBe("malformed_response");
      expect(failure.message).not.toContain("ya29.test-access-token");
    }
  });

  it("fails closed with a typed error when the transport itself rejects", async () => {
    const transport: OAuthTokenTransport = async () => {
      throw new Error(`transport detail ${code}`);
    };

    const failure = await capture(() => client().exchangeAuthorizationCode({ code, codeVerifier: verifier, clientSecret, transport }));

    expect(failure).toBeInstanceOf(GoogleOAuthTokenError);
    expect((failure as GoogleOAuthTokenError).code).toBe("network_error");
    expect(failure.message).not.toContain(code);
    expect(failure.message).not.toContain("transport detail");
  });
});

describe("granted OAuth scope validation", () => {
  it("accepts exactly the configured drive.readonly scope", () => {
    expect(validateGrantedScope({ grantedScope: scope, requiredScope: scope, allowedScopes: [scope] })).toBe(scope);
  });

  it("normalises repeated and whitespace-padded granted scopes", () => {
    expect(validateGrantedScope({ grantedScope: ` ${scope}  ${scope} `, requiredScope: scope, allowedScopes: [scope] })).toBe(scope);
  });

  it("fails closed when the granted scope omits drive.readonly", () => {
    for (const grantedScope of ["", "   ", "https://www.googleapis.com/auth/drive.metadata.readonly"]) {
      const failure = captureSync(() => validateGrantedScope({ grantedScope, requiredScope: scope, allowedScopes: [scope] }));
      expect(failure).toBeInstanceOf(GoogleOAuthScopeError);
      expect((failure as GoogleOAuthScopeError).code).toBe("required_scope_missing");
    }
  });

  it("fails closed when the granted scope is broader than the allowed set", () => {
    const failure = captureSync(() =>
      validateGrantedScope({
        grantedScope: `${scope} https://www.googleapis.com/auth/drive`,
        requiredScope: scope,
        allowedScopes: [scope]
      })
    );
    expect(failure).toBeInstanceOf(GoogleOAuthScopeError);
    expect((failure as GoogleOAuthScopeError).code).toBe("unexpected_scope");
  });
});
