# Changelog

All notable changes to `@chainvue/verusid-oauth` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.5

### Fixed

- **PKCE `code_verifier` is now RFC 7636-compliant.** `randomValue()` used
  `crypto.randomBytes(24)`, which produces a 32-character base64url string — below
  RFC 7636 §4.1's 43-character minimum. RFC-compliant authorization servers (e.g.
  Ory Hydra) reject the token exchange with such a verifier, breaking
  `completeLogin()`. It now uses `crypto.randomBytes(32)` → a 43-character verifier
  (the value also seeds `state`/`nonce`, for which the extra length is harmless).
  Added a regression test asserting the verifier length stays within 43–128.

> Note: the committed `version` field lagged the npm-published releases (0.1.2–0.1.4
> were published without a corresponding changelog). This is the first tracked entry;
> 0.1.5 supersedes the published 0.1.4.
