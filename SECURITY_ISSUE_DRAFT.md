## Summary
A security review identified authentication and origin-validation gaps in API handlers. The sensitive API protections were remediated by commit `8ea2374`, but the loopback Origin check still uses unsafe prefix matching.

## Severity
Medium for the residual finding; the earlier High findings are considered remediated.

## Residual Finding: Origin Prefix Validation
`is_loopback_origin` currently uses `starts_with`:

- `http://127.0.0.1...`
- `http://localhost...`

This is not a strict origin/host check. For example, a prefix such as `http://127.0.0.1.evil.example` is not an exact loopback host but could match the current implementation. The CORS predicate and mutation `Origin` validation both rely on this helper.

## Affected Areas
- `crates/estatetrace/src/api.rs`: `is_loopback_origin`
- `crates/estatetrace/src/api.rs`: CORS `AllowOrigin` predicate
- `crates/estatetrace/src/api.rs`: `origin_ok`
- `crates/estatetrace/src/api.rs`: `require_mutation`

## Risk / Impact
A malicious Origin with a loopback-like prefix could potentially pass the application-level check, weakening the intended loopback-only browser boundary. The risk is increased when combined with other local-origin/browser conditions.

## Reproduction (Conceptual)
1. Send a mutation with `Origin: http://127.0.0.1.evil.example`.
2. Observe whether `is_loopback_origin` incorrectly accepts the prefix.
3. Repeat with `Origin: http://localhost.evil.example`.

## Expected Behavior
- Parse the Origin as a URL.
- Require an HTTP or HTTPS scheme.
- Require an exact loopback host: `127.0.0.1`, `localhost`, or `[::1]` if IPv6 loopback is supported.
- Reject user-info, malformed URLs, `null`, and lookalike suffix/prefix hosts.
- Apply the same strict helper to CORS and mutation validation.

## Remediation Added by Commit `8ea2374`
- Added persistent session tokens to application state.
- Protected sensitive read handlers with `require_session`.
- Protected state-changing handlers with `require_mutation`.
- Left `/api/health` and `/api/session` public.
- Added auth and mutation tests.

## Proposed Remediation
1. Replace string-prefix checks with strict URL parsing and exact host comparison.
2. Include IPv6 loopback (`[::1]`) only if it is within the application's supported bind/origin matrix.
3. Add tests for lookalike hosts, malformed origins, `null`, and valid loopback origins.
4. Centralize the helper for CORS and mutation checks so they cannot diverge.

## Test Coverage to Add
- `http://127.0.0.1.evil.example` is rejected.
- `http://localhost.evil.example` is rejected.
- `http://127.0.0.1@evil.example` is rejected.
- `null` is rejected.
- Exact loopback origins remain accepted.
