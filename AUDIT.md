# Codebase Audit: verusid-oauth

Audit date: 2026-06-08

Scope: read-only end-to-end audit of the TypeScript SDK repository. This file records the repository-specific findings, commands, results, and remediation roadmap.

## Repository Understanding

- Stack: TypeScript ESM package for Node.js 20+.
- Package manager: npm with `package-lock.json`.
- Main entry point: `src/index.ts`.
- Build system: `tsc`, output to `dist`.
- Tests: Node built-in test runner against built output in `test/sdk.test.js`.
- CI/CD: GitHub Actions runs `npm ci`, typecheck, tests, build, and `npm pack --dry-run`; release workflow publishes to npm with provenance.
- External services: Ory Hydra public endpoint for token exchange/discovery/JWKS; Hydra admin endpoint for access-token introspection unless `accessTokenVerifier` is supplied.

## Commands Run

| Command | Result | Notes |
|---|---|---|
| `git -C verusid-oauth status --short --branch` | Pass | Clean, on `main...origin/main` before audit file creation. |
| `rg --files verusid-oauth` | Pass | Mapped repository files. |
| `sed` / `nl` read-only inspections | Pass | Reviewed source, tests, package metadata, TypeScript config, CI/release workflows, README. |
| `test -d verusid-oauth/node_modules` | Exit 1 | Dependencies were not installed in the fresh clone. |
| `npm test` | Fail expected | Failed at `tsc: command not found` because `node_modules` was absent. |
| `npm run typecheck` | Fail expected | Failed at `tsc: command not found` because `node_modules` was absent. |
| `npm audit --package-lock-only` | Pass | `found 0 vulnerabilities`. |

## Executive Summary

Overall risk: Medium.

The SDK has a compact implementation, strong TypeScript settings, clear package metadata, good tests for state/nonce/PKCE, ID token verification, OIDC cache behavior, custom access-token verification, and token redaction. The main correctness risk is identity binding: the SDK compares Verus claims between ID token and access-token introspection, but it does not require the OIDC `sub` claim to equal `verus_id`.

## Prioritized Findings

| Priority | Category | Finding | Evidence | Impact | Effort | Confidence |
|---|---|---|---|---|---|---|
| P1 | Correctness/Security | SDK does not require OIDC `sub` to equal `verus_id`. | `src/index.ts` `buildVerifiedSession()` sets `subject` from `claims.sub || idClaims.verus_id` without equality check. | High | S | High |
| P2 | Security/Operations | Default local secrets and HTTP URLs are returned by `createConfig()` unless production guard is called by the app. | `src/index.ts` `createConfig()` defaults; `assertProductionConfig()` exists but is opt-in. | Medium | S | High |
| P2 | Reliability | OIDC discovery/JWKS fetch assumes JSON responses and may surface generic failures for malformed or non-JSON responses. | `src/index.ts` `fetchJson()` calls `response.json()` directly. | Medium | S | Medium |
| P3 | Developer Experience | No lint or format script. | `package.json` scripts only include build/typecheck/test/doctor. | Low | S | High |

## Detailed Findings

### Enforce OIDC Subject To Verus Identity Binding

- Category: Correctness/Security
- Priority: P1
- Impact: High
- Effort: S
- Confidence: High
- Evidence: In `src/index.ts`, `buildVerifiedSession()` extracts Verus claims and verifies ID/access Verus claim equality, then returns `subject: idTokenVerification.claims?.sub || idClaims.verus_id`. It does not reject a verified ID token where `sub` differs from `verus_id`.
- Why it matters: Applications may authorize by `subject` while displaying or storing `verus_id`. If those diverge, the SDK can produce an internally inconsistent session.
- Recommended fix: Reject sessions when `sub` is present and does not equal `idClaims.verus_id`. Prefer requiring `sub` for Hydra-issued OIDC sessions if compatibility allows.
- Suggested tests: Add a regression test where a signed ID token contains `sub: "iOtherAddress"` and `verus_id: "iUserAddress"` with matching access-token Verus claims; `completeLogin()` should reject with `VERUS_CLAIMS_MISMATCH`.
- Risks / migration notes: If any existing deployment intentionally uses a non-Verus `sub`, this is a breaking behavior change. Document the required subject contract.

### Production Defaults Are Opt-In Guarded

- Category: Security/Operations
- Priority: P2
- Impact: Medium
- Effort: S
- Confidence: High
- Evidence: `createConfig()` defaults to local HTTP URLs and local example secrets. `getProductionConfigErrors()` and `assertProductionConfig()` catch these, but only callers that invoke the guard are protected.
- Why it matters: SDK consumers can accidentally deploy with local secrets or HTTP issuer/callback settings if they copy minimal usage without the guard.
- Recommended fix: Strengthen README examples to call `assertProductionConfig()` under `NODE_ENV=production`; consider exporting a `createProductionConfig()` helper that validates immediately.
- Suggested tests: Existing production config tests are good; add an example-app startup test that proves production mode refuses defaults.
- Risks / migration notes: Avoid making `createConfig()` throw unconditionally, since current local demo behavior depends on local defaults.

### Harden OIDC JSON Fetch Errors

- Category: Reliability
- Priority: P2
- Impact: Medium
- Effort: S
- Confidence: Medium
- Evidence: `fetchJson()` directly awaits `response.json()` and only checks `response.ok` after parsing.
- Why it matters: Non-JSON upstream errors can produce lower-signal exceptions and make diagnostics harder during issuer/JWKS outages.
- Recommended fix: Read text, parse JSON defensively, include status and endpoint label in the verification diagnostic after redaction.
- Suggested tests: Discovery endpoint returns HTML/empty body/500 JSON; SDK reports stable `ID_TOKEN_VERIFICATION_FAILED` diagnostics without leaking tokens.
- Risks / migration notes: Keep diagnostics concise and redacted.

## Architecture Assessment

The SDK is appropriately compact. A single source module is acceptable at current size, but verification concerns are becoming separable: config, token transport, JWT verification, Verus claim/session building, and diagnostics. Split only when adding features would otherwise make `src/index.ts` harder to reason about.

## Security Assessment

Confirmed strengths:

- State comparison uses `crypto.timingSafeEqual`.
- Login request generation includes nonce and PKCE.
- ID token verification checks signature, issuer, audience, nonce, expiry, and `at_hash` when present.
- Access-token Verus claims are compared with ID-token Verus claims.
- Structured diagnostics redact token and secret fields.

Confirmed issue:

- Missing explicit `sub === verus_id` binding.

Recommended hardening:

- Enforce subject binding.
- Keep production guard prominent in all examples.
- Add defensive non-JSON upstream error handling.

## Test Strategy

Highest-value tests:

- Reject `sub` and `verus_id` mismatch.
- Reject missing `sub` if the project chooses to require it.
- Discovery/JWKS malformed response diagnostics.
- Custom `accessTokenVerifier` throwing or timing out.

## Master Roadmap

| Order | Task | Why | Impact | Effort | Dependencies |
|---|---|---|---|---|---|
| 1 | Enforce `sub === verus_id` during session building. | Prevent identity ambiguity. | High | S | Contract decision on missing `sub`. |
| 2 | Add regression tests for subject mismatch. | Lock the security behavior. | High | S | Task 1. |
| 3 | Improve `fetchJson()` malformed-response diagnostics. | Better operational debugging. | Medium | S | None. |
| 4 | Update README production example to call `assertProductionConfig()`. | Prevent unsafe copy-paste. | Medium | XS | None. |
| 5 | Add lint/format scripts. | Improve maintainability. | Low | S | Tool choice. |

## Concrete Refactor Proposals

- Add a small helper near `buildVerifiedSession()`:
  - `subjectMatchesVerusId(claims, verusClaims)`
  - Return false when `claims.sub` exists and differs from `verusClaims.verus_id`.
- Include `subjectMatches` in the failed session diagnostic.
- Keep the public session shape unchanged after validation.

## Open Questions

- Should `sub` be mandatory for every accepted session, or only required to match when present?
