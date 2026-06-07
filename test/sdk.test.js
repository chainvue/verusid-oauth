import assert from "node:assert/strict"
import crypto from "node:crypto"
import test from "node:test"

import {
  buildAuthorizationUrl,
  buildVerifiedSession,
  clearOidcCache,
  computeAtHash,
  createConfig,
  createVerusOAuthClient,
  extractVerusClaims,
  getConfigWarnings,
  getProductionConfigErrors,
  toPublicSession,
  validateState,
  VerusOAuthError,
  VerusOAuthErrorCode,
  verifyIdToken,
  verusClaimsMatch,
} from "../dist/index.js"

const config = createConfig({
  LOCAL_HOST: "192.168.0.160",
  HYDRA_PUBLIC_URL: "http://192.168.0.160:4444",
  HYDRA_ADMIN_URL: "http://127.0.0.1:4445",
  CLIENT_ID: "verus-express-login",
  CLIENT_SECRET: "secret",
  REDIRECT_URI: "http://192.168.0.160:5560/callback",
})

const verusClaims = {
  verus_id: "iUserAddress",
  verus_id_name: "user@",
  verus_chain: "VRSCTEST",
  verus_auth_method: "verus_login_consent",
  verus_login_at: 1780828245,
}

test("authorization URL contains exact VerusID login parameters", () => {
  const url = buildAuthorizationUrl(config, "state-123", "nonce-123")

  assert.equal(url.origin, "http://192.168.0.160:4444")
  assert.equal(url.pathname, "/oauth2/auth")
  assert.equal(url.searchParams.get("client_id"), "verus-express-login")
  assert.equal(url.searchParams.get("response_type"), "code")
  assert.equal(url.searchParams.get("scope"), "openid offline verusid")
  assert.equal(url.searchParams.get("redirect_uri"), "http://192.168.0.160:5560/callback")
  assert.equal(url.searchParams.get("state"), "state-123")
  assert.equal(url.searchParams.get("nonce"), "nonce-123")
})

test("client factory creates authorization URL with state and nonce", () => {
  const client = createVerusOAuthClient(config)
  const loginRequest = client.createLoginRequest()

  assert.ok(loginRequest.state)
  assert.ok(loginRequest.nonce)
  assert.ok(loginRequest.codeVerifier)
  assert.equal(loginRequest.authorizationUrl.searchParams.get("scope"), "openid offline verusid")
  assert.equal(loginRequest.authorizationUrl.searchParams.get("state"), loginRequest.state)
  assert.equal(loginRequest.authorizationUrl.searchParams.get("nonce"), loginRequest.nonce)
  assert.equal(loginRequest.authorizationUrl.searchParams.get("code_challenge_method"), "S256")
  assert.equal(
    loginRequest.authorizationUrl.searchParams.get("code_challenge"),
    crypto.createHash("sha256").update(loginRequest.codeVerifier).digest("base64url"),
  )
})

test("config warnings distinguish LAN placeholder from compatibility default", () => {
  const placeholderWarnings = getConfigWarnings(createConfig({
    LOCAL_HOST: "<LAN-IP>",
  }))
  const compatibilityWarnings = getConfigWarnings(createConfig())
  const explicitLanWarnings = getConfigWarnings(createConfig({
    LOCAL_HOST: "192.168.1.25",
  }))

  assert.ok(placeholderWarnings.some((warning) => warning.includes("<LAN-IP>")))
  assert.ok(compatibilityWarnings.some((warning) => warning.includes("compatibility default")))
  assert.equal(explicitLanWarnings.length, 0)
  assert.equal(createConfig().localHost, "192.168.0.160")
})

test("production config errors reject local and public HTTP settings", () => {
  const localErrors = getProductionConfigErrors(createConfig())
  const validErrors = getProductionConfigErrors(createConfig({
    LOCAL_HOST: "app.example.com",
    HYDRA_PUBLIC_URL: "https://hydra.example.com",
    HYDRA_ADMIN_URL: "http://127.0.0.1:4445",
    CLIENT_SECRET: "production-client-secret",
    SESSION_SECRET: "production-session-secret",
    REDIRECT_URI: "https://app.example.com/callback",
  }))
  const publicAdminErrors = getProductionConfigErrors(createConfig({
    LOCAL_HOST: "app.example.com",
    HYDRA_PUBLIC_URL: "https://hydra.example.com",
    HYDRA_ADMIN_URL: "http://hydra-admin.example.com:4445",
    CLIENT_SECRET: "production-client-secret",
    SESSION_SECRET: "production-session-secret",
    REDIRECT_URI: "https://app.example.com/callback",
  }))
  const malformedErrors = getProductionConfigErrors({
    ...createConfig({
      LOCAL_HOST: "app.example.com",
      HYDRA_PUBLIC_URL: "not a url",
      HYDRA_ADMIN_URL: "also not a url",
      REDIRECT_URI: "not a url",
      CLIENT_SECRET: "production-client-secret",
      SESSION_SECRET: "production-session-secret",
    }),
    port: Number.NaN,
    timeoutMs: 0,
  })
  const insecureIssuerErrors = getProductionConfigErrors(createConfig({
    LOCAL_HOST: "app.example.com",
    HYDRA_PUBLIC_URL: "http://hydra.example.com",
    HYDRA_ADMIN_URL: "http://127.0.0.1:4445",
    CLIENT_SECRET: "production-client-secret",
    SESSION_SECRET: "production-session-secret",
    REDIRECT_URI: "https://app.example.com/callback",
  }))
  const scopeErrors = getProductionConfigErrors(createConfig({
    LOCAL_HOST: "app.example.com",
    HYDRA_PUBLIC_URL: "https://hydra.example.com",
    HYDRA_ADMIN_URL: "http://127.0.0.1:4445",
    CLIENT_SECRET: "production-client-secret",
    SESSION_SECRET: "production-session-secret",
    REDIRECT_URI: "https://app.example.com/callback",
    SCOPES: "openid verusid",
  }))

  assert.ok(localErrors.some((error) => error.includes("REDIRECT_URI")))
  assert.ok(localErrors.some((error) => error.includes("HYDRA_PUBLIC_URL")))
  assert.ok(localErrors.some((error) => error.includes("CLIENT_SECRET")))
  assert.ok(localErrors.some((error) => error.includes("SESSION_SECRET")))
  assert.ok(localErrors.some((error) => error.includes("LOCAL_HOST")))
  assert.deepEqual(validErrors, [])
  assert.ok(publicAdminErrors.some((error) => error.includes("HYDRA_ADMIN_URL")))
  assert.ok(malformedErrors.some((error) => error.includes("PORT")))
  assert.ok(malformedErrors.some((error) => error.includes("OAUTH_HTTP_TIMEOUT_MS")))
  assert.ok(malformedErrors.some((error) => error.includes("REDIRECT_URI")))
  assert.ok(malformedErrors.some((error) => error.includes("HYDRA_PUBLIC_URL")))
  assert.ok(malformedErrors.some((error) => error.includes("HYDRA_ADMIN_URL")))
  assert.ok(insecureIssuerErrors.some((error) => error.includes("HYDRA_PUBLIC_URL")))
  assert.ok(scopeErrors.some((error) => error.includes("SCOPES")))
})

test("state validation rejects missing and mismatched state", () => {
  assert.equal(validateState(null, "returned").ok, false)
  assert.equal(validateState("saved", null).ok, false)
  assert.equal(validateState("saved", "tampered").ok, false)
  assert.equal(validateState("saved", "saved").ok, true)
})

test("Verus claim extraction ignores profile and email claims", () => {
  const claims = extractVerusClaims({
    ...verusClaims,
    email: "user@example.com",
    email_verified: true,
    name: "User Example",
    preferred_username: "user",
  })

  assert.deepEqual(claims, verusClaims)
})

test("Verus claim comparison fails on mismatched ID and introspection claims", () => {
  assert.equal(verusClaimsMatch(verusClaims, verusClaims), true)
  assert.equal(
    verusClaimsMatch(verusClaims, { ...verusClaims, verus_id: "iDifferentAddress" }),
    false,
  )
})

test("verified session is sanitized and requires matching ID/access claims", () => {
  const tokenResult = {
    ok: true,
    body: {
      scope: "openid offline verusid",
      access_token: "access-token",
      id_token: "id-token",
      refresh_token: "refresh-token",
    },
  }
  const verified = buildVerifiedSession(
    tokenResult,
    { verified: true, claims: { sub: "iUserAddress", ...verusClaims } },
    { body: { active: true, ext: verusClaims } },
  )
  const mismatched = buildVerifiedSession(
    tokenResult,
    { verified: true, claims: { sub: "iUserAddress", ...verusClaims } },
    { body: { active: true, ext: { ...verusClaims, verus_id: "iDifferentAddress" } } },
  )

  assert.equal(verified.ok, true)
  assert.equal(verified.subject, "iUserAddress")
  assert.equal(verified.refreshTokenPresent, true)
  assert.equal(mismatched.ok, false)
})

test("verified session rejects OIDC subject that does not match Verus ID", () => {
  const tokenResult = {
    ok: true,
    body: {
      scope: "openid offline verusid",
      access_token: "access-token",
      id_token: "id-token",
      refresh_token: "refresh-token",
    },
  }
  const verified = buildVerifiedSession(
    tokenResult,
    { verified: true, claims: { sub: "iDifferentSubject", ...verusClaims } },
    { body: { active: true, ext: verusClaims } },
  )

  assert.equal(verified.ok, false)
  assert.match(verified.error, /subject/)
})

test("toPublicSession never returns raw tokens", () => {
  const publicSession = toPublicSession({
    ok: true,
    subject: "iUserAddress",
    verus: verusClaims,
    grantedScope: "openid offline verusid",
    refreshTokenPresent: true,
    tokens: {
      access_token: "access-token",
      id_token: "id-token",
      refresh_token: "refresh-token",
    },
  })

  assert.equal(publicSession.tokens, undefined)
  assert.equal(publicSession.ok, undefined)
  assert.equal(publicSession.subject, "iUserAddress")
  assert.equal(publicSession.refreshTokenPresent, true)
})

test("client completeLogin returns sanitized session unless raw tokens are requested", async () => {
  clearOidcCache()
  const { token, accessToken, jwk } = createSignedIdToken({
    nonce: "saved-nonce",
    atHashAccessToken: "access-token-value",
  })
  const fetchMock = installFetchMock({ token, accessToken, jwk })
  const originalFetch = fetchMock.originalFetch

  try {
    const client = createVerusOAuthClient(config)
    const loginRequest = client.createLoginRequest()
    const sanitized = await client.completeLogin({
      code: "returned-code",
      codeVerifier: loginRequest.codeVerifier,
      returnedState: "saved-state",
      expectedState: "saved-state",
      expectedNonce: "saved-nonce",
    })
    const raw = await client.completeLogin({
      code: "returned-code",
      codeVerifier: loginRequest.codeVerifier,
      returnedState: "saved-state",
      expectedState: "saved-state",
      expectedNonce: "saved-nonce",
      includeRawTokens: true,
    })

    assert.equal(fetchMock.tokenBodies[0].get("code_verifier"), loginRequest.codeVerifier)
    assert.equal(sanitized.tokens, undefined)
    assert.equal(sanitized.subject, "iUserAddress")
    assert.equal(raw.tokens.access_token, "access-token-value")
    assert.equal(raw.tokens.refresh_token, "refresh-token-value")
  } finally {
    global.fetch = originalFetch
    clearOidcCache()
  }
})

test("client completeLogin requires saved PKCE verifier before token exchange", async () => {
  const originalFetch = global.fetch
  let tokenExchangeCalled = false
  global.fetch = async () => {
    tokenExchangeCalled = true
    return textJsonResponse({})
  }

  try {
    const client = createVerusOAuthClient(config)
    await assert.rejects(
      client.completeLogin({
        code: "returned-code",
        returnedState: "saved-state",
        expectedState: "saved-state",
        expectedNonce: "saved-nonce",
      }),
      (error) => {
        assert.equal(error instanceof VerusOAuthError, true)
        assert.equal(error.code, VerusOAuthErrorCode.MISSING_CODE_VERIFIER)
        return true
      },
    )
    assert.equal(tokenExchangeCalled, false)
  } finally {
    global.fetch = originalFetch
  }
})

test("client completeLogin can use a custom access token verifier", async () => {
  clearOidcCache()
  const { token, accessToken, jwk } = createSignedIdToken({
    nonce: "saved-nonce",
    atHashAccessToken: "access-token-value",
  })
  const fetchMock = installFetchMock({ token, accessToken, jwk })
  const verifierCalls = []

  try {
    const client = createVerusOAuthClient({
      ...config,
      accessTokenVerifier: (input) => {
        verifierCalls.push(input)
        return { active: true, claims: verusClaims }
      },
    })
    const session = await client.completeLogin({
      code: "returned-code",
      codeVerifier: "saved-code-verifier",
      returnedState: "saved-state",
      expectedState: "saved-state",
      expectedNonce: "saved-nonce",
    })

    assert.equal(session.subject, "iUserAddress")
    assert.equal(verifierCalls.length, 1)
    assert.equal(verifierCalls[0].accessToken, "access-token-value")
    assert.equal(verifierCalls[0].tokenSet.id_token, token)
    assert.equal(verifierCalls[0].idTokenClaims.verus_id, "iUserAddress")
    assert.equal(fetchMock.introspectionCalls, 0)
  } finally {
    global.fetch = fetchMock.originalFetch
    clearOidcCache()
  }
})

test("client completeLogin rejects inactive and mismatched custom verifier results", async () => {
  clearOidcCache()
  const { token, accessToken, jwk } = createSignedIdToken({
    nonce: "saved-nonce",
    atHashAccessToken: "access-token-value",
  })
  const inactiveFetchMock = installFetchMock({ token, accessToken, jwk })

  try {
    const client = createVerusOAuthClient({
      ...config,
      accessTokenVerifier: () => ({ active: false, claims: verusClaims }),
    })
    await assert.rejects(
      client.completeLogin({
        code: "returned-code",
        codeVerifier: "saved-code-verifier",
        returnedState: "saved-state",
        expectedState: "saved-state",
        expectedNonce: "saved-nonce",
      }),
      (error) => {
        assert.equal(error instanceof VerusOAuthError, true)
        assert.equal(error.code, VerusOAuthErrorCode.ACCESS_TOKEN_INTROSPECTION_FAILED)
        return true
      },
    )
  } finally {
    global.fetch = inactiveFetchMock.originalFetch
    clearOidcCache()
  }

  const mismatchFetchMock = installFetchMock({ token, accessToken, jwk })
  try {
    const client = createVerusOAuthClient({
      ...config,
      accessTokenVerifier: () => ({ active: true, claims: { ...verusClaims, verus_id: "iDifferentAddress" } }),
    })
    await assert.rejects(
      client.completeLogin({
        code: "returned-code",
        codeVerifier: "saved-code-verifier",
        returnedState: "saved-state",
        expectedState: "saved-state",
        expectedNonce: "saved-nonce",
      }),
      (error) => {
        assert.equal(error instanceof VerusOAuthError, true)
        assert.equal(error.code, VerusOAuthErrorCode.VERUS_CLAIMS_MISMATCH)
        return true
      },
    )
  } finally {
    global.fetch = mismatchFetchMock.originalFetch
    clearOidcCache()
  }
})

test("structured errors expose stable codes and redact token diagnostics", async () => {
  const originalFetch = global.fetch
  global.fetch = async () => textJsonResponse({
    error: "invalid_grant",
    access_token: "secret-access-token",
    id_token: "secret-id-token",
  }, false, 400)

  try {
    const client = createVerusOAuthClient(config)
    await assert.rejects(
      client.completeLogin({
        code: "bad-code",
        codeVerifier: "saved-code-verifier",
        returnedState: "saved-state",
        expectedState: "saved-state",
        expectedNonce: "saved-nonce",
      }),
      (error) => {
        assert.equal(error instanceof VerusOAuthError, true)
        assert.equal(error.code, "TOKEN_EXCHANGE_FAILED")
        assert.doesNotMatch(JSON.stringify(error.diagnostics), /secret-access-token|secret-id-token/)
        return true
      },
    )
  } finally {
    global.fetch = originalFetch
  }
})

test("token exchange transport failures expose stable codes without leaking diagnostics", async () => {
  const originalFetch = global.fetch
  global.fetch = async () => {
    throw new Error("network failed with secret-access-token and secret-id-token")
  }

  try {
    const client = createVerusOAuthClient(config)
    await assert.rejects(
      client.completeLogin({
        code: "bad-code",
        codeVerifier: "saved-code-verifier",
        returnedState: "saved-state",
        expectedState: "saved-state",
        expectedNonce: "saved-nonce",
      }),
      (error) => {
        assert.equal(error instanceof VerusOAuthError, true)
        assert.equal(error.code, VerusOAuthErrorCode.TOKEN_EXCHANGE_FAILED)
        assert.doesNotMatch(JSON.stringify(error.diagnostics), /secret-access-token|secret-id-token/)
        assert.match(JSON.stringify(error.diagnostics), /request_failed/)
        return true
      },
    )
  } finally {
    global.fetch = originalFetch
  }
})

test("ID token verification checks signature, issuer, audience, nonce, expiry, and at_hash", async () => {
  clearOidcCache()
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  })
  const accessToken = "access-token-value"
  const jwk = publicKey.export({ format: "jwk" })
  jwk.kid = "test-key"
  jwk.use = "sig"
  const token = signJwt(privateKey, {
    alg: "RS256",
    kid: "test-key",
    typ: "JWT",
  }, {
    iss: "http://192.168.0.160:4444",
    aud: "verus-express-login",
    sub: "iUserAddress",
    nonce: "expected-nonce",
    exp: Math.floor(Date.now() / 1000) + 300,
    at_hash: computeAtHash(accessToken, "RS256"),
    ...verusClaims,
  })

  const originalFetch = global.fetch
  global.fetch = async (url) => {
    if (String(url).endsWith("/.well-known/openid-configuration")) {
      return jsonResponse({
        issuer: "http://192.168.0.160:4444",
        jwks_uri: "http://192.168.0.160:4444/.well-known/jwks.json",
      })
    }
    if (String(url).endsWith("/.well-known/jwks.json")) {
      return jsonResponse({ keys: [jwk] })
    }
    throw new Error(`Unexpected fetch ${url}`)
  }

  try {
    const verified = await verifyIdToken(config, token, accessToken, "expected-nonce")
    const badNonce = await verifyIdToken(config, token, accessToken, "wrong-nonce")
    const badHash = await verifyIdToken(config, token, "wrong-access-token", "expected-nonce")

    assert.equal(verified.verified, true)
    assert.equal(badNonce.verified, false)
    assert.equal(badNonce.checks.find((check) => check.label === "Nonce")?.ok, false)
    assert.equal(badHash.verified, false)
    assert.equal(badHash.checks.find((check) => check.label === "at_hash")?.ok, false)
  } finally {
    global.fetch = originalFetch
    clearOidcCache()
  }
})

test("ID token verification reports invalid OIDC JSON responses", async () => {
  clearOidcCache()
  const { token, accessToken } = createSignedIdToken({
    nonce: "expected-nonce",
    atHashAccessToken: "access-token-value",
  })
  const originalFetch = global.fetch
  global.fetch = async () => ({
    ok: true,
    status: 200,
    statusText: "OK",
    text: async () => "<html>not json</html>",
  })

  try {
    const result = await verifyIdToken(config, token, accessToken, "expected-nonce")

    assert.equal(result.verified, false)
    assert.match(result.error, /Invalid JSON response/)
  } finally {
    global.fetch = originalFetch
    clearOidcCache()
  }
})

test("OIDC discovery and JWKS are cached per issuer", async () => {
  clearOidcCache()
  const { token, accessToken, jwk } = createSignedIdToken({
    nonce: "expected-nonce",
    atHashAccessToken: "access-token-value",
  })
  const calls = { discovery: 0, jwks: 0 }
  const originalFetch = global.fetch
  global.fetch = async (url) => {
    if (String(url).endsWith("/.well-known/openid-configuration")) {
      calls.discovery += 1
      return jsonResponse({
        issuer: "http://192.168.0.160:4444",
        jwks_uri: "http://192.168.0.160:4444/.well-known/jwks.json",
      })
    }
    if (String(url).endsWith("/.well-known/jwks.json")) {
      calls.jwks += 1
      return jsonResponse({ keys: [jwk] })
    }
    throw new Error(`Unexpected fetch ${url}`)
  }

  try {
    assert.equal((await verifyIdToken(config, token, accessToken, "expected-nonce")).verified, true)
    assert.equal((await verifyIdToken(config, token, accessToken, "expected-nonce")).verified, true)
    assert.deepEqual(calls, { discovery: 1, jwks: 1 })
  } finally {
    global.fetch = originalFetch
    clearOidcCache()
  }
})

test("OIDC discovery and JWKS caches refresh after TTL", async () => {
  clearOidcCache()
  const { token, accessToken, jwk } = createSignedIdToken({
    nonce: "expected-nonce",
    atHashAccessToken: "access-token-value",
    expiresInSeconds: 900,
  })
  const calls = { discovery: 0, jwks: 0 }
  const originalFetch = global.fetch
  const originalDateNow = Date.now
  let now = originalDateNow()
  Date.now = () => now
  global.fetch = async (url) => {
    if (String(url).endsWith("/.well-known/openid-configuration")) {
      calls.discovery += 1
      return jsonResponse({
        issuer: "http://192.168.0.160:4444",
        jwks_uri: "http://192.168.0.160:4444/.well-known/jwks.json",
      })
    }
    if (String(url).endsWith("/.well-known/jwks.json")) {
      calls.jwks += 1
      return jsonResponse({ keys: [jwk] })
    }
    throw new Error(`Unexpected fetch ${url}`)
  }

  try {
    assert.equal((await verifyIdToken(config, token, accessToken, "expected-nonce")).verified, true)
    now += 5 * 60 * 1000 + 1
    assert.equal((await verifyIdToken(config, token, accessToken, "expected-nonce")).verified, true)
    assert.deepEqual(calls, { discovery: 2, jwks: 2 })
  } finally {
    global.fetch = originalFetch
    Date.now = originalDateNow
    clearOidcCache()
  }
})

function signJwt(privateKey, header, claims) {
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString("base64url")
  const encodedClaims = Buffer.from(JSON.stringify(claims)).toString("base64url")
  const signer = crypto.createSign("RSA-SHA256")
  signer.update(`${encodedHeader}.${encodedClaims}`)
  signer.end()
  return `${encodedHeader}.${encodedClaims}.${signer.sign(privateKey).toString("base64url")}`
}

function jsonResponse(body) {
  return {
    ok: true,
    status: 200,
    statusText: "OK",
    json: async () => body,
    text: async () => JSON.stringify(body),
  }
}

function textJsonResponse(body, ok = true, status = 200) {
  return {
    ok,
    status,
    statusText: ok ? "OK" : "Bad Request",
    text: async () => JSON.stringify(body),
  }
}

function createSignedIdToken({ nonce, atHashAccessToken, expiresInSeconds = 300 }) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  })
  const accessToken = "access-token-value"
  const jwk = publicKey.export({ format: "jwk" })
  jwk.kid = "test-key"
  jwk.use = "sig"

  return {
    accessToken,
    jwk,
    token: signJwt(privateKey, {
      alg: "RS256",
      kid: "test-key",
      typ: "JWT",
    }, {
      iss: "http://192.168.0.160:4444",
      aud: "verus-express-login",
      sub: "iUserAddress",
      nonce,
      exp: Math.floor(Date.now() / 1000) + expiresInSeconds,
      at_hash: computeAtHash(atHashAccessToken, "RS256"),
      ...verusClaims,
    }),
  }
}

function installFetchMock({ token, accessToken, jwk }) {
  const originalFetch = global.fetch
  const tokenBodies = []
  let introspectionCalls = 0
  global.fetch = async (url, init) => {
    const value = String(url)
    if (value.endsWith("/oauth2/token")) {
      tokenBodies.push(init.body)
      return textJsonResponse({
        access_token: accessToken,
        id_token: token,
        refresh_token: "refresh-token-value",
        token_type: "bearer",
        expires_in: 3600,
        scope: "openid offline verusid",
      })
    }
    if (value.endsWith("/.well-known/openid-configuration")) {
      return jsonResponse({
        issuer: "http://192.168.0.160:4444",
        jwks_uri: "http://192.168.0.160:4444/.well-known/jwks.json",
      })
    }
    if (value.endsWith("/.well-known/jwks.json")) {
      return jsonResponse({ keys: [jwk] })
    }
    if (value.endsWith("/admin/oauth2/introspect")) {
      introspectionCalls += 1
      return textJsonResponse({
        active: true,
        sub: "iUserAddress",
        scope: "openid offline verusid",
        ext: verusClaims,
      })
    }
    throw new Error(`Unexpected fetch ${url}`)
  }
  return {
    originalFetch,
    tokenBodies,
    get introspectionCalls() {
      return introspectionCalls
    },
  }
}
