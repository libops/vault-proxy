# Lightweight Go Proxy for Vault

This is a lightweight reverse proxy designed to sit in front of a HashiCorp Vault instance. It adds an additional authorization layer for admin access while allowing specific OIDC-related routes to be public.

## Security Logic

This proxy implements the following logic for every incoming request:

1. **Public Routes**: The request path is checked against a list of public route prefixes (defined in `config.yaml`). If it matches, the request is forwarded directly to Vault without any checks.

2. **Protected Routes**: If the path is not public, the proxy requires the request to have a header named `X-Admin-Token`.

3. **Token Validation**: The value of this header MUST be a valid Google OAuth 2.0 access token. The proxy validates the token by calling Google's tokeninfo endpoint to verify:
   - The token is valid and not expired
   - The email claim is present and verified

4. **Admin Check**: After the token is proven valid, the proxy checks the `email` and `email_verified` claims. If `email_verified` is true and the email is in the admin list, access is granted.

5. **Access Denied**: If the header is missing, the token is invalid, or the user is not in the admin list, the proxy returns a `401 Unauthorized` or `403 Forbidden` error.

6. **Forwarding**: If access is granted, the `X-Admin-Token` header is removed from the request, and the original request (including any original `Authorization` header containing a Vault token) is forwarded to Vault.

This allows an admin to make an authenticated Vault API request while proving their identity to the proxy simultaneously.

## Configuration

Configuration is managed via either a YAML file or the `VAULT_PROXY_YAML` environment variable.

### Option 1: YAML File

Create a `config.yaml` file:

```yaml
vault_addr: "http://127.0.0.1:8200"
port: 8080
admin_emails:
  - admin@mycorp.com
  - ops@mycorp.com
public_routes:
  - /.well-known/
  - /v1/identity/oidc/
  - /v1/auth/oidc/
  - /v1/auth/userpass/
  - /v1/sys/health
```

### Option 2: Environment Variable

Set the `VAULT_PROXY_YAML` environment variable with the YAML configuration as a string:

```bash
export VAULT_PROXY_YAML='
vault_addr: "http://127.0.0.1:8200"
port: 8080
admin_emails:
  - admin@mycorp.com
  - ops@mycorp.com
public_routes:
  - /.well-known/
  - /v1/identity/oidc/
  - /v1/auth/oidc/
  - /v1/auth/userpass/
  - /v1/sys/health
'
```

**Note**: If `VAULT_PROXY_YAML` is set, it takes precedence over the `-config` flag.

### Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| `vault_addr` | Yes | The full URL of the upstream Vault server (e.g., `http://127.0.0.1:8200`) |
| `admin_emails` | Yes | List of Google email addresses that are allowed admin access |
| `public_routes` | No | List of URL prefixes to allow through without any checks |
| `port` | No | The port for this proxy to listen on. Defaults to `8080` |

### Example Public Routes

To support customer authentication (OIDC and username/password) and the OIDC Identity Broker flow, these paths should be public:

- `/.well-known/`: For OIDC discovery (e.g., `/.well-known/openid-configuration`)
- `/v1/identity/oidc/`: For Vault's OIDC provider endpoints (like `/authorize` and `/token`)
- `/v1/auth/oidc/`: For OIDC authentication endpoints (login, callback)
- `/v1/auth/userpass/`: For username/password authentication endpoints
- `/v1/sys/health`: For Vault health checks (monitoring, load balancers)

## How to Get an Admin Token

An admin can get their Google access token (the value for `X-Admin-Token`) using the `gcloud` CLI:

```bash
export ADMIN_TOKEN=$(gcloud auth print-access-token)
curl -H "X-Vault-Token: <YOUR_VAULT_TOKEN>" \
     -H "X-Admin-Token: $ADMIN_TOKEN" \
     http://localhost:8080/v1/sys/health
```
