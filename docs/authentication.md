# Authentication

## Development

With `ART_ENV=development` and `ART_AUTH_PROVIDER=development`, use:

```text
Authorization: Bearer development:<viewer|operator|admin>:<subject>
```

The token is validated by `DevelopmentHeaderAuthenticator`; malformed roles, empty or
whitespace-containing subjects, missing bearer headers, and non-development composition
are rejected. The React client keeps this credential only in memory. Refresh or logout
clears it. It is never written to local/session storage or logs.

## OIDC resource server

`OidcIdentityProvider` validates signed JWT access tokens using configured HTTPS JWKS.
It allow-lists asymmetric algorithms, requires `kid`, signature, `iss`, `aud`, `sub`,
`iat`, and `exp`, evaluates `nbf` when present, and permits bounded clock skew. JWKS is
cached with an expiry and refreshed once for an unknown `kid`, supporting safe rotation.
`alg=none`, shared-secret algorithm confusion, unknown issuers/audiences/keys, expired
tokens, and invalid signatures fail with a generic 401 response.

Roles are read from verified `roles` or `role` claims. Permissions are always derived
from the local matrix. MFA assurance is never inferred: `ART_OIDC_MFA_CLAIM` names one
exact, top-level claim in the already signature-verified access token and
`ART_OIDC_MFA_VALUES` is a comma-separated exact-value allow-list. A string claim or any
string member of an array claim must match that allow-list. Missing, malformed, or
unconfigured claims produce `mfa_satisfied=false`.

The caller's **organization** is read from the verified claim named by
`ART_OIDC_ORGANIZATION_CLAIM` (default `org_id`) and is never taken from a header, query or
body. A token without it (or with a malformed value) fails authentication unless the operator
explicitly sets `ART_OIDC_DEFAULT_ORGANIZATION` for a single-tenant deployment. The development
authenticator accepts `Bearer development:<role>:<subject>[#<organization>]`.

Required production settings are `ART_AUTH_PROVIDER=oidc`, `ART_OIDC_ISSUER`,
`ART_OIDC_AUDIENCE`, and `ART_OIDC_JWKS_URL`. OIDC endpoints must use HTTPS. Missing or
partial configuration fails startup.

When `ART_MFA_REQUIRED_FOR_SENSITIVE_ACTIONS=true`, both MFA settings are mandatory for
OIDC. Startup fails closed without that trusted contract. An HTTP header, request body,
browser state, role claim, or unverified JWT content can never raise assurance.

The browser contract accepts an injected `BrowserOidcAdapter` that performs Authorization
Code with PKCE and provider logout. No implicit flow, client secret, local password store,
recovery workflow, or home-grown MFA is implemented. The deployment must supply the IdP
SDK/configuration and the IdP remains responsible for password, recovery, revocation,
SSO, and MFA policy.

## Delivery status

- **IMPLEMENTED:** strict JWT/JWKS validation, rotation refresh, provider-neutral
  identity, explicit MFA claim interpretation, verified organization claim, and development
  authentication. Verified with locally signed tokens and a mock JWKS only — see
  `docs/integrations.md` for the live-tenant check that is still pending.
- **READY WITH EXTERNAL DEPENDENCY:** browser OIDC PKCE adapter and an actual IdP tenant,
  policy, client registration, logout/revocation, and key lifecycle.
- **NOT IMPLEMENTED:** local password database, custom MFA enrollment/recovery, and an
  embedded identity provider.
