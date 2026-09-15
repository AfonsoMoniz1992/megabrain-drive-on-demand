import { createHash } from "node:crypto";
import type { BrokerRuntimeConfig } from "./config.js";

const GOOGLE_AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";

type GoogleOAuthConfiguration = Pick<BrokerRuntimeConfig, "googleClientId" | "googleCallbackUri" | "googleDriveScope">;

/** Injected network boundary. Tests supply a fake; production falls back to the default fetch transport. */
export interface OAuthTransportRequest {
  url: string;
  method: "POST";
  headers: Readonly<Record<string, string>>;
  body: string;
}

export interface OAuthTransportResponse {
  status: number;
  body: string;
}

export type OAuthTokenTransport = (request: OAuthTransportRequest) => Promise<OAuthTransportResponse>;

export type GoogleOAuthTokenErrorCode = "network_error" | "token_endpoint_error" | "malformed_response";

/**
 * Typed token-exchange failure. The message is a fixed string and never carries
 * the authorization code, the PKCE verifier, any token, the client secret or the
 * raw provider body.
 */
export class GoogleOAuthTokenError extends Error {
  readonly code: GoogleOAuthTokenErrorCode;

  constructor(code: GoogleOAuthTokenErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "GoogleOAuthTokenError";
    this.code = code;
  }
}

export type GoogleOAuthScopeErrorCode = "required_scope_missing" | "unexpected_scope";

/** Typed granted-scope violation. Fails closed; the message is a fixed, non-reflecting string. */
export class GoogleOAuthScopeError extends Error {
  readonly code: GoogleOAuthScopeErrorCode;

  constructor(code: GoogleOAuthScopeErrorCode, message: string) {
    super(message);
    this.name = "GoogleOAuthScopeError";
    this.code = code;
  }
}

export interface AuthorizationCodeTokens {
  accessToken: string;
  tokenType: string;
  refreshToken?: string;
  expiresIn?: number;
  scope: string;
}

export interface OAuthAccessToken {
  accessToken: string;
  tokenType: string;
  scope: string;
  expiresIn?: number;
}

function pkceS256Challenge(verifier: string): string {
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

const defaultTransport: OAuthTokenTransport = async (request) => {
  const response = await fetch(request.url, {
    method: request.method,
    headers: request.headers,
    body: request.body
  });
  return { status: response.status, body: await response.text() };
};

/** Parses the token response strictly: a partial or unexpected body is a failure, never a partial result. */
function parseTokenResponse(status: number, raw: string): AuthorizationCodeTokens {
  if (!Number.isInteger(status) || status < 200 || status >= 300) {
    throw new GoogleOAuthTokenError("token_endpoint_error", "Google token endpoint rejected the authorization-code exchange");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new GoogleOAuthTokenError("malformed_response", "Google token response could not be parsed");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new GoogleOAuthTokenError("malformed_response", "Google token response was not a JSON object");
  }
  const candidate = parsed as Record<string, unknown>;
  if (typeof candidate.access_token !== "string" || candidate.access_token.length === 0) {
    throw new GoogleOAuthTokenError("malformed_response", "Google token response omitted a usable access_token");
  }
  if (typeof candidate.token_type !== "string" || candidate.token_type.length === 0) {
    throw new GoogleOAuthTokenError("malformed_response", "Google token response omitted a usable token_type");
  }
  if (typeof candidate.scope !== "string" || candidate.scope.length === 0) {
    throw new GoogleOAuthTokenError("malformed_response", "Google token response omitted a usable scope");
  }

  const tokens: AuthorizationCodeTokens = {
    accessToken: candidate.access_token,
    tokenType: candidate.token_type,
    scope: candidate.scope
  };
  if (candidate.refresh_token !== undefined) {
    if (typeof candidate.refresh_token !== "string" || candidate.refresh_token.length === 0) {
      throw new GoogleOAuthTokenError("malformed_response", "Google token response carried an unusable refresh_token");
    }
    tokens.refreshToken = candidate.refresh_token;
  }
  if (candidate.expires_in !== undefined) {
    if (!Number.isInteger(candidate.expires_in) || (candidate.expires_in as number) <= 0) {
      throw new GoogleOAuthTokenError("malformed_response", "Google token response carried an unusable expires_in");
    }
    tokens.expiresIn = candidate.expires_in as number;
  }
  return tokens;
}

/**
 * Validates the granted scope set. It must include the required Drive readonly
 * scope and must not contain any scope outside the configured allowed set;
 * otherwise it fails closed with a typed error.
 */
export function validateGrantedScope(input: {
  grantedScope: string;
  requiredScope: string;
  allowedScopes: readonly string[];
}): string {
  const granted = new Set(
    (typeof input.grantedScope === "string" ? input.grantedScope : "")
      .split(/\s+/)
      .filter((value) => value.length > 0)
  );
  if (!granted.has(input.requiredScope)) {
    throw new GoogleOAuthScopeError(
      "required_scope_missing",
      "Granted OAuth scope does not include the required Drive readonly scope"
    );
  }
  const allowed = new Set(input.allowedScopes);
  for (const value of granted) {
    if (!allowed.has(value)) {
      throw new GoogleOAuthScopeError("unexpected_scope", "Granted OAuth scope includes a scope that is not allowed");
    }
  }
  return [...granted].join(" ");
}

/**
 * Local OAuth helper. It builds authorization requests and performs the
 * authorization-code exchange through an injected transport; it never logs or
 * returns raw provider material beyond the validated token set.
 */
export class GoogleOAuthClient {
  constructor(private readonly config: GoogleOAuthConfiguration) {}

  createAuthorizationUrl(input: { oauthState: string; pkceVerifier: string }): string {
    const query = new URLSearchParams({
      client_id: this.config.googleClientId,
      redirect_uri: this.config.googleCallbackUri,
      response_type: "code",
      scope: this.config.googleDriveScope,
      state: input.oauthState,
      code_challenge: pkceS256Challenge(input.pkceVerifier),
      code_challenge_method: "S256",
      // Offline access plus an explicit consent prompt is what makes Google
      // issue a refresh token on the consent screen; without it a repeat
      // authorization silently omits one.
      access_type: "offline",
      prompt: "consent"
    });
    return `${GOOGLE_AUTHORIZATION_ENDPOINT}?${query.toString()}`;
  }

  async exchangeAuthorizationCode(input: {
    code: string;
    codeVerifier: string;
    clientSecret: string;
    transport?: OAuthTokenTransport;
  }): Promise<AuthorizationCodeTokens> {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: input.code,
      code_verifier: input.codeVerifier,
      client_id: this.config.googleClientId,
      client_secret: input.clientSecret,
      redirect_uri: this.config.googleCallbackUri
    }).toString();

    const transport = input.transport ?? defaultTransport;
    let response: OAuthTransportResponse;
    try {
      response = await transport({
        url: GOOGLE_TOKEN_ENDPOINT,
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body
      });
    } catch {
      // The transport cause may embed request material; it is deliberately dropped.
      throw new GoogleOAuthTokenError("network_error", "Google token endpoint could not be reached");
    }

    return parseTokenResponse(response.status, response.body);
  }

  /**
   * Exchanges the stored refresh token for a fresh read-only access token.
   * The response is parsed strictly and the granted scope is validated against
   * the allowed set before anything is returned. Failures are typed with fixed,
   * non-reflecting messages and never carry token material.
   */
  async refreshAccessToken(input: {
    refreshToken: string;
    clientSecret: string;
    transport?: OAuthTokenTransport;
    requiredScope?: string;
    allowedScopes?: readonly string[];
  }): Promise<OAuthAccessToken> {
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: input.refreshToken,
      client_id: this.config.googleClientId,
      client_secret: input.clientSecret
    }).toString();

    const transport = input.transport ?? defaultTransport;
    let response: OAuthTransportResponse;
    try {
      response = await transport({
        url: GOOGLE_TOKEN_ENDPOINT,
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body
      });
    } catch {
      // The transport cause may embed request material; it is deliberately dropped.
      throw new GoogleOAuthTokenError("network_error", "Google token endpoint could not be reached");
    }

    const tokens = parseTokenResponse(response.status, response.body);
    const scope = validateGrantedScope({
      grantedScope: tokens.scope,
      requiredScope: input.requiredScope ?? this.config.googleDriveScope,
      allowedScopes: input.allowedScopes ?? [this.config.googleDriveScope]
    });

    const refreshed: OAuthAccessToken = {
      accessToken: tokens.accessToken,
      tokenType: tokens.tokenType,
      scope
    };
    if (tokens.expiresIn !== undefined) refreshed.expiresIn = tokens.expiresIn;
    return refreshed;
  }
}
