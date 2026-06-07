# @chainvue/verusid-oauth

TypeScript SDK for server-side VerusID OAuth/OIDC login.

This package helps confidential Node.js backends start a VerusID OAuth login, exchange the returned authorization code, verify the OIDC ID token through Hydra discovery and JWKS, introspect the access token, compare Verus claims, and return a sanitized application session.

## Install

```sh
npm install @chainvue/verusid-oauth
```

## Usage

```ts
import {
  VerusOAuthError,
  createConfig,
  createVerusOAuthClient,
} from "@chainvue/verusid-oauth"

const config = createConfig(process.env)
const verusOAuth = createVerusOAuthClient(config)

app.get("/login", (req, res) => {
  const login = verusOAuth.createLoginRequest()
  req.session.oauth = { state: login.state, nonce: login.nonce }
  res.redirect(login.authorizationUrl.toString())
})

app.get("/callback", async (req, res, next) => {
  try {
    const saved = req.session.oauth || {}
    delete req.session.oauth

    req.session.login = await verusOAuth.completeLogin({
      code: req.query.code,
      returnedState: req.query.state,
      expectedState: saved.state,
      expectedNonce: saved.nonce,
    })

    res.redirect("/")
  } catch (error) {
    if (error instanceof VerusOAuthError) {
      res.status(400).json({ error: error.code, message: error.message })
      return
    }
    next(error)
  }
})
```

`completeLogin()` returns a sanitized session by default:

```json
{
  "subject": "i...",
  "verus": {
    "verus_id": "i...",
    "verus_id_name": "name@",
    "verus_chain": "VRSCTEST",
    "verus_auth_method": "verus_login_consent",
    "verus_login_at": 1780828245
  },
  "grantedScope": "openid offline verusid",
  "refreshTokenPresent": true
}
```

Raw OAuth tokens are returned only when `includeRawTokens: true` is passed to `completeLogin()`.

## Environment

- `HYDRA_PUBLIC_URL`, default `http://$LOCAL_HOST:4444`
- `HYDRA_ADMIN_URL`, default `http://127.0.0.1:4445`
- `CLIENT_ID`, default `verus-express-login`
- `CLIENT_SECRET`, default `verus-express-secret`
- `REDIRECT_URI`, default `http://$LOCAL_HOST:5560/callback`
- `SCOPES`, default `openid offline verusid`
- `OAUTH_HTTP_TIMEOUT_MS`, default `10000`

## Release Checklist

Use this checklist for future releases. npm versions are immutable, so push the
release tag only after the package version and release contents are final.

1. Update the `package.json` version.
2. Run `npm test`.
3. Commit the release changes.
4. Tag the commit as `vX.Y.Z`.
5. Push the tag.
6. Confirm GitHub Actions publishes the package.
7. Verify the published version with:

```sh
npm view @chainvue/verusid-oauth version
```

npm Trusted Publishing must remain configured for package
`@chainvue/verusid-oauth` with:

- GitHub repository: `chainvue/verusid-oauth`
- Workflow: `release.yml`
- Permission: npm publish

## License

MIT
