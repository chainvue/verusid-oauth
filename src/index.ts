import crypto from "node:crypto"

export const DEFAULT_SCOPE = "openid offline verusid"
const DEFAULT_LOCAL_HOST = "192.168.0.160"
const DEFAULT_TIMEOUT_MS = 10000

const discoveryCache = new Map<string, Promise<OidcDiscovery>>()
const jwksCache = new Map<string, Promise<JsonWebKeySet>>()

export const VERUS_CLAIM_NAMES = [
  "verus_id",
  "verus_id_name",
  "verus_chain",
  "verus_auth_method",
  "verus_login_at",
] as const

export type VerusClaimName = (typeof VERUS_CLAIM_NAMES)[number]

export type VerusClaims = {
  verus_id: string
  verus_id_name?: string
  verus_chain: string
  verus_auth_method: string
  verus_login_at?: number | string
}

export type VerusOAuthConfig = {
  port: number
  localHost: string
  hydraPublicUrl: string
  hydraAdminUrl: string
  clientId: string
  clientSecret: string
  redirectUri: string
  scope: string
  sessionSecret: string
  showDebugTokens: boolean
  timeoutMs: number
}

export type CompleteLoginOptions = {
  code?: unknown
  returnedState?: unknown
  expectedState?: unknown
  expectedNonce?: unknown
  includeRawTokens?: boolean
}

export type PublicVerusSession = {
  subject: string
  verus: VerusClaims
  grantedScope: string
  refreshTokenPresent: boolean
}

export type RawTokenSet = {
  access_token?: string
  id_token?: string
  refresh_token?: string
}

export type VerifiedVerusSession = PublicVerusSession & {
  ok: true
  tokens: RawTokenSet
}

export const VerusOAuthErrorCode = Object.freeze({
  STATE_MISMATCH: "STATE_MISMATCH",
  MISSING_CODE: "MISSING_CODE",
  TOKEN_EXCHANGE_FAILED: "TOKEN_EXCHANGE_FAILED",
  ID_TOKEN_VERIFICATION_FAILED: "ID_TOKEN_VERIFICATION_FAILED",
  ACCESS_TOKEN_INTROSPECTION_FAILED: "ACCESS_TOKEN_INTROSPECTION_FAILED",
  VERUS_CLAIMS_MISMATCH: "VERUS_CLAIMS_MISMATCH",
})

export type VerusOAuthErrorCodeValue =
  (typeof VerusOAuthErrorCode)[keyof typeof VerusOAuthErrorCode]

export class VerusOAuthError extends Error {
  code: VerusOAuthErrorCodeValue
  diagnostics: unknown

  constructor(
    code: VerusOAuthErrorCodeValue,
    message: string,
    diagnostics: unknown = {},
  ) {
    super(message)
    this.name = "VerusOAuthError"
    this.code = code
    this.diagnostics = redactDiagnostics(diagnostics)
  }
}

type TokenResult = {
  ok: boolean
  status?: number
  statusText?: string
  body: Record<string, any>
  error?: unknown
}

type IdTokenVerification = {
  ok: boolean
  verified: boolean
  claims: Record<string, any> | null
  header?: Record<string, any> | null
  checks: Array<{ label: string; ok: boolean }>
  error?: string | null
  issuer?: string
}

type IntrospectionResult = {
  body?: {
    active?: boolean
    ext?: Record<string, any>
    [key: string]: any
  }
}

type OidcDiscovery = {
  issuer: string
  jwks_uri: string
}

type JsonWebKeySet = {
  keys?: VerusJsonWebKey[]
}

type VerusJsonWebKey = JsonWebKey & Record<string, unknown> & {
  kid?: string
  use?: string
}

export function createConfig(env: Record<string, string | undefined> = process.env): VerusOAuthConfig {
  const localHost = env.LOCAL_HOST || DEFAULT_LOCAL_HOST
  const port = env.PORT || "5560"

  return {
    port: Number(port),
    localHost,
    hydraPublicUrl: env.HYDRA_PUBLIC_URL || `http://${localHost}:4444`,
    hydraAdminUrl: env.HYDRA_ADMIN_URL || "http://127.0.0.1:4445",
    clientId: env.CLIENT_ID || "verus-express-login",
    clientSecret: env.CLIENT_SECRET || "verus-express-secret",
    redirectUri: env.REDIRECT_URI || `http://${localHost}:5560/callback`,
    scope: env.SCOPES || DEFAULT_SCOPE,
    sessionSecret: env.SESSION_SECRET || "local-express-login-session-secret",
    showDebugTokens: env.SHOW_DEBUG_TOKENS === "1",
    timeoutMs: Number(env.OAUTH_HTTP_TIMEOUT_MS || DEFAULT_TIMEOUT_MS),
  }
}

export function createVerusOAuthClient(config: VerusOAuthConfig) {
  return new VerusOAuthClient(config)
}

export class VerusOAuthClient {
  config: VerusOAuthConfig

  constructor(config: VerusOAuthConfig) {
    this.config = config
  }

  createLoginRequest() {
    const state = randomValue()
    const nonce = randomValue()
    return {
      authorizationUrl: buildAuthorizationUrl(this.config, state, nonce),
      state,
      nonce,
    }
  }

  async completeLogin(
    options: CompleteLoginOptions = {},
  ): Promise<PublicVerusSession | VerifiedVerusSession | null | undefined> {
    const {
      code,
      returnedState,
      expectedState,
      expectedNonce,
      includeRawTokens = false,
    } = options

    const stateValidation = validateState(expectedState, returnedState)
    if (!stateValidation.ok) {
      throw new VerusOAuthError(VerusOAuthErrorCode.STATE_MISMATCH, stateValidation.message)
    }
    if (!code) {
      throw new VerusOAuthError(VerusOAuthErrorCode.MISSING_CODE, "Hydra did not return an authorization code.")
    }

    const tokenResult = await exchangeCode(this.config, String(code))
    if (!tokenResult.ok) {
      throw new VerusOAuthError(
        VerusOAuthErrorCode.TOKEN_EXCHANGE_FAILED,
        "Hydra rejected the authorization code.",
        { tokenResult },
      )
    }

    const idTokenVerification = await verifyIdToken(
      this.config,
      tokenResult.body.id_token,
      tokenResult.body.access_token,
      expectedNonce,
    )
    if (!idTokenVerification.verified) {
      throw new VerusOAuthError(
        VerusOAuthErrorCode.ID_TOKEN_VERIFICATION_FAILED,
        "ID token verification failed.",
        { idTokenVerification },
      )
    }

    const introspectionResult = tokenResult.body.access_token
      ? await introspectAccessToken(this.config, tokenResult.body.access_token)
      : null
    if (!introspectionResult?.body?.active) {
      throw new VerusOAuthError(
        VerusOAuthErrorCode.ACCESS_TOKEN_INTROSPECTION_FAILED,
        "Hydra did not report an active VerusID access token.",
        { introspectionResult },
      )
    }

    const verifiedSession = buildVerifiedSession(tokenResult, idTokenVerification, introspectionResult)
    if (!verifiedSession.ok) {
      throw new VerusOAuthError(
        VerusOAuthErrorCode.VERUS_CLAIMS_MISMATCH,
        verifiedSession.error || "OAuth response did not pass VerusID verification.",
        { verifiedSession },
      )
    }

    return includeRawTokens ? verifiedSession : toPublicSession(verifiedSession)
  }

  toPublicSession(session: VerifiedVerusSession | null | undefined) {
    return toPublicSession(session)
  }
}

export function randomValue() {
  return crypto.randomBytes(24).toString("base64url")
}

export function buildAuthorizationUrl(config: VerusOAuthConfig, state: string, nonce: string) {
  const authUrl = new URL("/oauth2/auth", config.hydraPublicUrl)
  authUrl.searchParams.set("client_id", config.clientId)
  authUrl.searchParams.set("response_type", "code")
  authUrl.searchParams.set("scope", config.scope)
  authUrl.searchParams.set("redirect_uri", config.redirectUri)
  authUrl.searchParams.set("state", state)
  authUrl.searchParams.set("nonce", nonce)
  return authUrl
}

export const createAuthorizationUrl = buildAuthorizationUrl

export function validateState(expectedState: unknown, returnedState: unknown) {
  if (!expectedState) {
    return { ok: false, message: "Missing saved state" }
  }
  if (!returnedState) {
    return { ok: false, message: "Missing returned state" }
  }

  const expected = Buffer.from(String(expectedState))
  const returned = Buffer.from(String(returnedState))
  if (expected.length !== returned.length || !crypto.timingSafeEqual(expected, returned)) {
    return { ok: false, message: "Returned state does not match saved state" }
  }

  return { ok: true, message: "State matched" }
}

export const validateOAuthState = validateState

export async function exchangeCode(config: VerusOAuthConfig, code: string) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: config.redirectUri,
  })

  return postForm(`${config.hydraPublicUrl}/oauth2/token`, body, {
    authorization: `Basic ${Buffer.from(`${config.clientId}:${config.clientSecret}`).toString("base64")}`,
  }, config)
}

export const exchangeCodeForTokens = exchangeCode

export async function introspectAccessToken(config: VerusOAuthConfig, accessToken: string) {
  return postForm(
    `${config.hydraAdminUrl}/admin/oauth2/introspect`,
    new URLSearchParams({ token: accessToken }),
    {},
    config,
  )
}

async function postForm(
  url: string,
  body: URLSearchParams,
  headers: Record<string, string> = {},
  config: Pick<VerusOAuthConfig, "timeoutMs"> = { timeoutMs: DEFAULT_TIMEOUT_MS },
): Promise<TokenResult> {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      ...headers,
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body,
    signal: AbortSignal.timeout(config.timeoutMs || DEFAULT_TIMEOUT_MS),
  })
  const text = await response.text()
  const parsed = parseJson(text) || { raw: text }

  return {
    ok: response.ok,
    status: response.status,
    statusText: response.statusText,
    body: parsed,
    error: response.ok ? null : parsed.error || response.statusText,
  }
}

export async function verifyIdToken(
  config: VerusOAuthConfig,
  token: unknown,
  accessToken: unknown,
  expectedNonce: unknown,
): Promise<IdTokenVerification> {
  const decoded = decodeJwt(token)
  if (!decoded.ok) {
    return { ok: false, verified: false, claims: null, checks: [], error: decoded.error }
  }

  const result: IdTokenVerification = {
    ok: false,
    verified: false,
    claims: decoded.claims,
    header: decoded.header,
    checks: [],
    error: null,
  }

  try {
    const discovery = await getDiscovery(config)
    const jwks = await getJwks(config, discovery.jwks_uri)
    const jwk = findJwk(jwks, decoded.header)

    result.issuer = discovery.issuer
    result.checks.push({ label: "JWKS key", ok: Boolean(jwk) })
    result.checks.push({ label: "Signature", ok: Boolean(jwk && verifyJwtSignature(String(token), decoded.header, jwk)) })
    result.checks.push({ label: "Issuer", ok: decoded.claims.iss === discovery.issuer })
    result.checks.push({ label: "Audience", ok: audienceIncludes(decoded.claims.aud, config.clientId) })
    result.checks.push({ label: "Nonce", ok: Boolean(expectedNonce && decoded.claims.nonce === expectedNonce) })
    result.checks.push({
      label: "Expiry",
      ok: typeof decoded.claims.exp === "number" && decoded.claims.exp > Math.floor(Date.now() / 1000),
    })

    if (decoded.claims.at_hash !== undefined) {
      result.checks.push({
        label: "at_hash",
        ok: Boolean(accessToken && computeAtHash(String(accessToken), decoded.header.alg) === decoded.claims.at_hash),
      })
    }

    result.verified = result.checks.every((check) => check.ok)
    result.ok = result.verified
    result.error = result.verified ? null : "ID token verification failed"
    return result
  } catch (error) {
    return { ...result, error: `ID token verification failed: ${error instanceof Error ? error.message : String(error)}` }
  }
}

async function getDiscovery(config: VerusOAuthConfig) {
  const issuerUrl = config.hydraPublicUrl.replace(/\/+$/, "")
  if (!discoveryCache.has(issuerUrl)) {
    discoveryCache.set(issuerUrl, fetchJson(`${issuerUrl}/.well-known/openid-configuration`, config))
  }
  return discoveryCache.get(issuerUrl) as Promise<OidcDiscovery>
}

async function getJwks(config: VerusOAuthConfig, jwksUri: string) {
  if (!jwksCache.has(jwksUri)) {
    jwksCache.set(jwksUri, fetchJson(jwksUri, config))
  }
  return jwksCache.get(jwksUri) as Promise<JsonWebKeySet>
}

export function clearOidcCache() {
  discoveryCache.clear()
  jwksCache.clear()
}

async function fetchJson<T>(
  url: string,
  config: Pick<VerusOAuthConfig, "timeoutMs"> = { timeoutMs: DEFAULT_TIMEOUT_MS },
): Promise<T> {
  const response = await fetch(url, {
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(config.timeoutMs || DEFAULT_TIMEOUT_MS),
  })
  const body = await response.json() as T & { error?: string }
  if (!response.ok) {
    throw new Error(body?.error || response.statusText)
  }
  return body
}

function decodeJwt(token: unknown) {
  if (!token) {
    return { ok: false as const, claims: null, header: null, error: "No ID token returned" }
  }

  const parts = String(token).split(".")
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
    return { ok: false as const, claims: null, header: null, error: "ID token is not a complete signed JWT" }
  }

  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"))
    const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"))
    if (!header || typeof header !== "object" || Array.isArray(header)) {
      return { ok: false as const, claims: null, header: null, error: "ID token header is not a JSON object" }
    }
    if (!claims || typeof claims !== "object" || Array.isArray(claims)) {
      return { ok: false as const, claims: null, header: null, error: "ID token payload is not a JSON object" }
    }
    return { ok: true as const, claims: claims as Record<string, any>, header: header as Record<string, any>, error: null }
  } catch (error) {
    return { ok: false as const, claims: null, header: null, error: `Could not decode ID token: ${error instanceof Error ? error.message : String(error)}` }
  }
}

function findJwk(jwks: JsonWebKeySet, header: Record<string, any> | null) {
  return (jwks.keys || []).find((key) => {
    if (header?.kid && key.kid !== header.kid) {
      return false
    }
    return key.use === undefined || key.use === "sig"
  })
}

export function verifyJwtSignature(token: string, header: Record<string, any> | null, jwk: VerusJsonWebKey) {
  if (header?.alg !== "RS256") {
    return false
  }
  const parts = String(token).split(".")
  const verifier = crypto.createVerify("RSA-SHA256")
  verifier.update(`${parts[0]}.${parts[1]}`)
  verifier.end()
  const publicKey = crypto.createPublicKey({ key: jwk, format: "jwk" })
  return verifier.verify(publicKey, Buffer.from(parts[2], "base64url"))
}

export function computeAtHash(accessToken: string, alg: string) {
  if (alg !== "RS256") {
    return null
  }
  const digest = crypto.createHash("sha256").update(accessToken).digest()
  return digest.subarray(0, digest.length / 2).toString("base64url")
}

function audienceIncludes(audience: unknown, expectedAudience: string) {
  return Array.isArray(audience)
    ? audience.includes(expectedAudience)
    : audience === expectedAudience
}

export function extractVerusClaims(source: unknown): VerusClaims | null {
  if (!source || typeof source !== "object") {
    return null
  }

  const claims: Record<string, string | number> = {}
  for (const name of VERUS_CLAIM_NAMES) {
    const value = (source as Record<string, unknown>)[name]
    if (value !== undefined && value !== null && value !== "") {
      claims[name] = value as string | number
    }
  }

  return claims.verus_id && claims.verus_chain && claims.verus_auth_method
    ? claims as VerusClaims
    : null
}

export function verusClaimsMatch(idClaims: VerusClaims | null, accessClaims: VerusClaims | null) {
  if (!idClaims || !accessClaims) {
    return false
  }

  return VERUS_CLAIM_NAMES.every((name) => {
    const idHasValue = idClaims[name] !== undefined && idClaims[name] !== null && idClaims[name] !== ""
    const accessHasValue = accessClaims[name] !== undefined && accessClaims[name] !== null && accessClaims[name] !== ""
    if (!idHasValue && !accessHasValue) {
      return true
    }
    return idHasValue && accessHasValue && String(idClaims[name]) === String(accessClaims[name])
  })
}

export const compareVerusClaims = verusClaimsMatch

export function buildVerifiedSession(
  tokenResult: TokenResult,
  idTokenVerification: IdTokenVerification,
  introspectionResult: IntrospectionResult | null,
): VerifiedVerusSession | {
  ok: false
  error: string
  idClaims: VerusClaims | null
  accessClaims: VerusClaims | null
  claimsMatch: boolean
} {
  const idClaims = extractVerusClaims(idTokenVerification.claims)
  const accessClaims = extractVerusClaims(introspectionResult?.body?.ext)
  const claimsMatch = verusClaimsMatch(idClaims, accessClaims)

  if (!tokenResult.ok || !idTokenVerification.verified || !introspectionResult?.body?.active || !claimsMatch || !idClaims) {
    return {
      ok: false,
      error: "OAuth response did not pass VerusID verification",
      idClaims,
      accessClaims,
      claimsMatch,
    }
  }

  return {
    ok: true,
    subject: idTokenVerification.claims?.sub || idClaims.verus_id,
    verus: idClaims,
    grantedScope: tokenResult.body.scope || "",
    refreshTokenPresent: Boolean(tokenResult.body.refresh_token),
    tokens: {
      access_token: tokenResult.body.access_token,
      id_token: tokenResult.body.id_token,
      refresh_token: tokenResult.body.refresh_token,
    },
  }
}

export async function completeVerusLogin(config: VerusOAuthConfig, options: CompleteLoginOptions) {
  return createVerusOAuthClient(config).completeLogin(options)
}

export function toPublicSession(session: VerifiedVerusSession | null | undefined) {
  if (!session) {
    return session
  }
  const { ok: _ok, tokens: _tokens, ...publicSession } = session
  return {
    ...publicSession,
    refreshTokenPresent: Boolean(session.refreshTokenPresent),
  }
}

function redactDiagnostics(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(redactDiagnostics)
  }
  if (!value || typeof value !== "object") {
    return value
  }
  const redacted: Record<string, unknown> = {}
  for (const [key, entry] of Object.entries(value)) {
    if (/token|secret|authorization/i.test(key)) {
      redacted[key] = "[redacted]"
    } else {
      redacted[key] = redactDiagnostics(entry)
    }
  }
  return redacted
}

function parseJson(value: string): Record<string, any> | null {
  try {
    return JSON.parse(value)
  } catch {
    return null
  }
}
