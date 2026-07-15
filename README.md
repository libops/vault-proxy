# Vault proxy

Vault proxy is the public Cloud Run sidecar for the LibOps Vault service. Vault
continues to authorize every Vault token and policy; the proxy adds a Google
administrator check to routes that are not explicitly required by customer
authentication or secret access flows.

## Request policy

- `GET /healthz` checks only that the proxy process can serve requests.
- A configured public route is forwarded without a Google administrator token.
- Every other route requires a valid Google access token in `X-Admin-Token`
  whose verified email is in `admin_emails`.
- `X-Admin-Token` is always removed before forwarding. Vault credentials such
  as `X-Vault-Token` and `Authorization` are preserved.
- Authentication failures return a generic `401`; logs record the denied path
  without the Google credential or token-validation details.

Version 2 replaces unsafe implicit prefixes with explicit path patterns. A
literal path matches exactly, `*` matches one complete segment, and a final
`/**` matches a subtree. For example,
`/v1/auth/userpass/login/**` permits login requests but does not expose
`/v1/auth/userpass/users/**`. Legacy routes ending in `/` are rejected so an
upgrade cannot silently retain the broader policy.

## Configuration

Set `VAULT_PROXY_YAML` or pass `-config /path/to/config.yaml`. Environment
configuration takes precedence. Unknown YAML fields, multiple YAML documents,
invalid ports, non-HTTP(S) upstreams, malformed emails, and invalid route
patterns fail startup.

```yaml
vault_addr: http://127.0.0.1:8200
port: 8080
admin_emails:
  - admin@example.com
public_routes:
  - /.well-known/**
  - /v1/identity/oidc/provider/*/.well-known/**
  - /v1/identity/oidc/provider/*/authorize
  - /v1/identity/oidc/provider/*/token
  - /v1/identity/oidc/provider/*/userinfo
  - /ui/vault/identity/oidc/provider/*/authorize
  - /v1/auth/oidc/oidc/auth_url
  - /v1/auth/oidc/oidc/callback
  - /ui/vault/auth/*/oidc/callback
  - /v1/auth/userpass/login/**
  - /v1/sys/health
```

The example patterns permit OIDC discovery/exchange and user login while
leaving role, provider, user, policy, and system management protected. Add
secret-engine subtrees only when downstream Vault policies are intended to be
the authorization boundary for those paths.

The provider paths follow Vault's
[OIDC provider API](https://developer.hashicorp.com/vault/api-docs/secret/identity/oidc-provider),
and the auth-method callback paths follow the
[JWT/OIDC auth API](https://developer.hashicorp.com/vault/api-docs/auth/jwt).

An administrator can supply a Google access token while independently passing
a Vault token:

```sh
curl \
  -H "X-Admin-Token: $(gcloud auth print-access-token)" \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  https://vault.example.com/v1/sys/policies/acl
```

Service-account access tokens must include the
`https://www.googleapis.com/auth/userinfo.email` scope so Google's tokeninfo
response contains the verified service-account email. Tokens without that
identity claim fail closed.

## Images and releases

Pull requests build, test, lint, build both native image architectures, and
scan them without registry credentials. Protected `main` and release tags use
the LibOps shared publisher to publish and keylessly sign the same manifest in:

- `ghcr.io/libops/vault-proxy`
- `us-docker.pkg.dev/libops-images/public/vault-proxy`

Cloud Run deployments must use the GAR image pinned by digest. Other consumers
should use GHCR and may also pin the signed digest. Repository releases use PR
title markers (`[major]`, `[minor]`, or the default patch increment).
