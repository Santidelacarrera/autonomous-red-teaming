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
from the local matrix. `amr` values such as `mfa`, `otp`, or `hwk` populate the assurance
context used by optional step-up policy.

Required production settings are `ART_AUTH_PROVIDER=oidc`, `ART_OIDC_ISSUER`,
`ART_OIDC_AUDIENCE`, and `ART_OIDC_JWKS_URL`. OIDC endpoints must use HTTPS. Missing or
partial configuration fails startup.

The browser contract accepts an injected `BrowserOidcAdapter` that performs Authorization
Code with PKCE and provider logout. No implicit flow, client secret, local password store,
recovery workflow, or home-grown MFA is implemented. The deployment must supply the IdP
SDK/configuration and the IdP remains responsible for password, recovery, revocation,
SSO, and MFA policy.
