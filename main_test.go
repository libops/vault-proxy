package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type tokenValidatorFunc func(context.Context, string, map[string]struct{}) error

func (fn tokenValidatorFunc) Validate(ctx context.Context, token string, admins map[string]struct{}) error {
	return fn(ctx, token, admins)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

type identityTokenProviderFunc func(context.Context, string) (string, error)

func (fn identityTokenProviderFunc) Token(ctx context.Context, audience string) (string, error) {
	return fn(ctx, audience)
}

func TestIsPublicRoute(t *testing.T) {
	routes := []string{
		"/.well-known/**",
		"/v1/identity/oidc/provider/*/authorize",
		"/v1/auth/userpass/login/**",
		"/v1/sys/health",
	}
	tests := []struct {
		path string
		want bool
	}{
		{"/.well-known/openid-configuration", true},
		{"/v1/identity/oidc/provider/default/authorize", true},
		{"/v1/identity/oidc/provider/default/config", false},
		{"/v1/auth/userpass/login", true},
		{"/v1/auth/userpass/login/alice", true},
		{"/v1/auth/userpass/users/alice", false},
		{"/v1/sys/health", true},
		{"/v1/sys/health/extra", false},
		{"/v1/sys/healthcheck", false},
		{"/v1/auth/userpass/login/../users/alice", false},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			if got := isPublicRoute(test.path, routes); got != test.want {
				t.Fatalf("isPublicRoute(%q) = %v, want %v", test.path, got, test.want)
			}
		})
	}
}

func TestValidatePublicRoutePattern(t *testing.T) {
	for _, pattern := range []string{
		"/v1/sys/health",
		"/v1/auth/userpass/login/**",
		"/v1/identity/oidc/provider/*/authorize",
	} {
		if err := validatePublicRoutePattern(pattern); err != nil {
			t.Errorf("valid pattern %q rejected: %v", pattern, err)
		}
	}
	for _, pattern := range []string{
		"v1/sys/health",
		"/v1/auth/oidc/",
		"/v1/**/config",
		"/v1/auth*",
		"/v1//health",
		"/v1/../sys/health",
	} {
		if err := validatePublicRoutePattern(pattern); err == nil {
			t.Errorf("invalid pattern %q accepted", pattern)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name       string
		yaml       string
		wantPort   int
		wantErr    string
		wantAdmins int
	}{
		{
			name: "valid and normalized",
			yaml: `vault_addr: http://127.0.0.1:8200
admin_emails:
  - Admin@Example.com
  - admin@example.com
public_routes:
  - /v1/sys/health
`,
			wantPort:   8080,
			wantAdmins: 1,
		},
		{
			name: "explicit port",
			yaml: `vault_addr: https://vault.example.com
port: 8443
admin_emails: [admin@example.com]
`,
			wantPort:   8443,
			wantAdmins: 1,
		},
		{
			name: "private upstream audience",
			yaml: `vault_addr: https://vault-runtime.example.run.app
vault_audience: https://vault-runtime.example.run.app
admin_emails: [admin@example.com]
`,
			wantPort:   8080,
			wantAdmins: 1,
		},
		{name: "unknown field", yaml: "vault_addr: http://vault:8200\nadmin_emails: [admin@example.com]\nsurprise: true\n", wantErr: "field surprise not found"},
		{name: "relative URL", yaml: "vault_addr: vault:8200\nadmin_emails: [admin@example.com]\n", wantErr: "must use http or https"},
		{name: "URL credentials", yaml: "vault_addr: https://user:pass@vault.example.com\nadmin_emails: [admin@example.com]\n", wantErr: "must not contain credentials"},
		{name: "URL path", yaml: "vault_addr: https://vault.example.com/v1\nadmin_emails: [admin@example.com]\n", wantErr: "must not contain a path"},
		{name: "audience with plaintext upstream", yaml: "vault_addr: http://vault:8200\nvault_audience: https://vault.example.run.app\nadmin_emails: [admin@example.com]\n", wantErr: "must use HTTPS"},
		{name: "audience path", yaml: "vault_addr: https://vault.example.run.app\nvault_audience: https://vault.example.run.app/path\nadmin_emails: [admin@example.com]\n", wantErr: "must not contain credentials, a path"},
		{name: "audience credentials", yaml: "vault_addr: https://vault.example.run.app\nvault_audience: https://user@example.run.app\nadmin_emails: [admin@example.com]\n", wantErr: "must not contain credentials"},
		{name: "empty admins", yaml: "vault_addr: http://vault:8200\nadmin_emails: ['   ']\n", wantErr: "invalid admin email"},
		{name: "invalid email", yaml: "vault_addr: http://vault:8200\nadmin_emails: [not-an-email]\n", wantErr: "invalid admin email"},
		{name: "invalid low port", yaml: "vault_addr: http://vault:8200\nport: -1\nadmin_emails: [admin@example.com]\n", wantErr: "between 1 and 65535"},
		{name: "invalid high port", yaml: "vault_addr: http://vault:8200\nport: 65536\nadmin_emails: [admin@example.com]\n", wantErr: "between 1 and 65535"},
		{name: "legacy route prefix", yaml: "vault_addr: http://vault:8200\nadmin_emails: [admin@example.com]\npublic_routes: [/v1/auth/userpass/]\n", wantErr: "canonical absolute path"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("VAULT_PROXY_YAML", "")
			configPath := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(configPath, []byte(test.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			config, err := loadConfig(configPath)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("loadConfig() error = %v, want substring %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if config.ListenPort != test.wantPort {
				t.Errorf("ListenPort = %d, want %d", config.ListenPort, test.wantPort)
			}
			if len(config.AdminEmails) != test.wantAdmins {
				t.Errorf("admin count = %d, want %d", len(config.AdminEmails), test.wantAdmins)
			}
		})
	}
}

func TestMetadataIdentityTokenProviderCachesValidToken(t *testing.T) {
	expires := time.Now().Add(time.Hour).Unix()
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, expires)))
	token := "header." + payload + ".signature"
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls++
		if request.Header.Get("Metadata-Flavor") != "Google" {
			t.Error("metadata request omitted Metadata-Flavor")
		}
		if request.URL.Query().Get("audience") != "https://vault-runtime.example.run.app" || request.URL.Query().Get("format") != "full" {
			t.Errorf("metadata query = %q", request.URL.RawQuery)
		}
		_, _ = w.Write([]byte(token))
	}))
	defer server.Close()

	provider := &metadataIdentityTokenProvider{client: server.Client(), endpoint: server.URL}
	for range 2 {
		got, err := provider.Token(context.Background(), "https://vault-runtime.example.run.app")
		if err != nil {
			t.Fatal(err)
		}
		if got != token {
			t.Fatalf("token = %q, want test token", got)
		}
	}
	if calls != 1 {
		t.Fatalf("metadata calls = %d, want one cached fetch", calls)
	}
}

func TestMetadataIdentityClientRejectsProxyAndRedirects(t *testing.T) {
	client := newMetadataIdentityHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T", client.Transport)
	}
	if transport.Proxy != nil || !transport.DisableKeepAlives {
		t.Fatal("metadata identity client permits a proxy or reusable plaintext connection")
	}
	if client.CheckRedirect == nil || !errors.Is(client.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
		t.Fatal("metadata identity client permits redirects")
	}
}

func TestIdentityTokenExpiryRejectsMalformedTokens(t *testing.T) {
	for _, token := range []string{"", "one.two", "one.%%%25.three", "one.e30.three"} {
		if _, err := identityTokenExpiry(token); err == nil {
			t.Errorf("identityTokenExpiry(%q) accepted malformed token", token)
		}
	}
}

func TestProxyAddsUpstreamIdentityWithoutReplacingVaultAuthorization(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("X-Serverless-Authorization"); got != "Bearer runtime-id-token" {
			t.Errorf("X-Serverless-Authorization = %q", got)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer vault-client-token" {
			t.Errorf("Authorization = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	config := testConfig(t, upstream.URL, []string{"/v1/sys/health"})
	config.VaultAudience = "https://vault-runtime.example.run.app"
	handler := createProxyHandlerWithDependencies(
		config,
		tokenValidatorFunc(func(context.Context, string, map[string]struct{}) error {
			t.Fatal("validator called for public route")
			return nil
		}),
		identityTokenProviderFunc(func(_ context.Context, audience string) (string, error) {
			if audience != config.VaultAudience {
				t.Fatalf("audience = %q", audience)
			}
			return "runtime-id-token", nil
		}),
	)
	request := httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil)
	request.Header.Set("Authorization", "Bearer vault-client-token")
	request.Header.Set("X-Serverless-Authorization", "Bearer attacker-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
}

func TestLoadConfigEnvironmentTakesPrecedence(t *testing.T) {
	t.Setenv("VAULT_PROXY_YAML", "vault_addr: http://env-vault:8200\nadmin_emails: [admin@example.com]\n")
	config, err := loadConfig(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if config.VaultTargetURL.Host != "env-vault:8200" {
		t.Fatalf("target = %q, want env-vault:8200", config.VaultTargetURL.Host)
	}
}

func TestGoogleTokenValidator(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("access_token") != "valid-token" {
			http.Error(w, "rejected", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(TokenInfo{Email: "ADMIN@example.com", EmailVerified: "true"})
	}))
	defer server.Close()

	validator := googleTokenValidator{client: server.Client(), endpoint: server.URL}
	admins := map[string]struct{}{"admin@example.com": {}}
	if err := validator.Validate(context.Background(), "valid-token", admins); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if err := validator.Validate(context.Background(), "invalid-token", admins); err == nil {
		t.Fatal("invalid token accepted")
	}
}

func TestGoogleTokenValidatorTransportErrorRedactsToken(t *testing.T) {
	const token = "secret-google-access-token"
	validator := googleTokenValidator{
		client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("request to %s failed", request.URL.String())
		})},
		endpoint: "https://oauth2.googleapis.com/tokeninfo",
	}

	err := validator.Validate(context.Background(), token, map[string]struct{}{"admin@example.com": {}})
	if err == nil {
		t.Fatal("transport failure accepted")
	}
	if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "access_token=") {
		t.Fatalf("validator error exposed token-bearing URL: %q", err)
	}
}

func TestValidateAdminIdentity(t *testing.T) {
	admins := map[string]struct{}{
		"admin@example.com": {},
		"api-production@libops-api.iam.gserviceaccount.com": {},
	}
	tests := []struct {
		name string
		info TokenInfo
		ok   bool
	}{
		{"verified user", TokenInfo{Email: "ADMIN@example.com", EmailVerified: "true"}, true},
		{"unverified user", TokenInfo{Email: "admin@example.com", EmailVerified: "false"}, false},
		{"unverified service account", TokenInfo{Email: "api-production@libops-api.iam.gserviceaccount.com", EmailVerified: "false"}, false},
		{"unknown user", TokenInfo{Email: "other@example.com", EmailVerified: "true"}, false},
		{"missing email", TokenInfo{EmailVerified: "true"}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateAdminIdentity(test.info, admins)
			if (err == nil) != test.ok {
				t.Fatalf("validateAdminIdentity() error = %v, ok want %v", err, test.ok)
			}
		})
	}
}

func TestProxyHandlerPublicRouteStripsAdminCredential(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Admin-Token"); got != "" {
			t.Errorf("upstream received X-Admin-Token %q", got)
		}
		if got := r.Header.Get("X-Vault-Token"); got != "vault-token" {
			t.Errorf("upstream X-Vault-Token = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer vault-credential" {
			t.Errorf("upstream Authorization = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler := createProxyHandlerWithValidator(testConfig(t, upstream.URL, []string{"/v1/sys/health"}), tokenValidatorFunc(func(context.Context, string, map[string]struct{}) error {
		t.Fatal("validator called for public route")
		return nil
	}))
	req := httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil)
	req.Header.Set("X-Admin-Token", "google-token")
	req.Header.Set("X-Vault-Token", "vault-token")
	req.Header.Set("Authorization", "Bearer vault-credential")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
}

func TestProxyHandlerProtectsManagementRoutes(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalls++
	}))
	defer upstream.Close()

	handler := createProxyHandlerWithValidator(testConfig(t, upstream.URL, []string{"/v1/auth/userpass/login/**"}), tokenValidatorFunc(func(context.Context, string, map[string]struct{}) error {
		return nil
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/auth/userpass/users/alice", nil))
	if response.Code != http.StatusUnauthorized || strings.TrimSpace(response.Body.String()) != "Unauthorized" {
		t.Fatalf("response = %d %q, want generic 401", response.Code, response.Body.String())
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream called %d times", upstreamCalls)
	}
}

func TestProxyHandlerProtectedRoute(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Admin-Token") != "" {
			t.Error("admin token leaked upstream")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()

	validator := tokenValidatorFunc(func(_ context.Context, token string, admins map[string]struct{}) error {
		if token != "allowed" {
			return errors.New("denied detail that must stay internal")
		}
		if _, ok := admins["admin@example.com"]; !ok {
			t.Error("admin allowlist missing")
		}
		return nil
	})
	handler := createProxyHandlerWithValidator(testConfig(t, upstream.URL, nil), validator)

	for _, test := range []struct {
		token string
		want  int
	}{
		{"", http.StatusUnauthorized},
		{"denied", http.StatusUnauthorized},
		{"allowed", http.StatusAccepted},
	} {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/sys/config/state", nil)
		if test.token != "" {
			req.Header.Set("X-Admin-Token", test.token)
		}
		handler.ServeHTTP(response, req)
		if response.Code != test.want {
			t.Errorf("token %q: status = %d, want %d", test.token, response.Code, test.want)
		}
		if test.want == http.StatusUnauthorized && strings.Contains(response.Body.String(), "denied detail") {
			t.Error("internal validation detail leaked to caller")
		}
	}
}

func TestProxyHandlerRedactsValidatorErrorsFromLogs(t *testing.T) {
	const sensitiveDetail = "secret-google-access-token"
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("denied request reached Vault")
	}))
	defer upstream.Close()

	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previousLogger)

	handler := createProxyHandlerWithValidator(testConfig(t, upstream.URL, nil), tokenValidatorFunc(func(context.Context, string, map[string]struct{}) error {
		return errors.New(sensitiveDetail)
	}))
	request := httptest.NewRequest(http.MethodGet, "/v1/sys/config/state", nil)
	request.Header.Set("X-Admin-Token", sensitiveDetail)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if strings.Contains(logs.String(), sensitiveDetail) {
		t.Fatalf("logs exposed validator credential: %q", logs.String())
	}
}

func TestProxyHandlerRemovesSpoofedForwardingHeaders(t *testing.T) {
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		for _, header := range []string{
			"Forwarded",
			"X-Forwarded-For",
			"X-Forwarded-Host",
			"X-Forwarded-Port",
			"X-Forwarded-Proto",
			"X-Real-IP",
			"X-Serverless-Authorization",
		} {
			if values := request.Header.Values(header); len(values) != 0 {
				t.Errorf("upstream received spoofable %s header %q", header, values)
			}
		}
		if request.Host != strings.TrimPrefix(upstream.URL, "http://") {
			t.Errorf("upstream Host = %q, want target host", request.Host)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler := createProxyHandlerWithValidator(testConfig(t, upstream.URL, []string{"/v1/sys/health"}), tokenValidatorFunc(func(context.Context, string, map[string]struct{}) error {
		t.Fatal("validator called for public route")
		return nil
	}))
	request := httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil)
	request.Header.Set("Forwarded", "for=198.51.100.10;host=attacker.example;proto=https")
	request.Header.Set("X-Forwarded-For", "198.51.100.10")
	request.Header.Set("X-Forwarded-Host", "attacker.example")
	request.Header.Set("X-Forwarded-Port", "443")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Real-IP", "198.51.100.10")
	request.Header.Set("X-Serverless-Authorization", "Bearer attacker-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
}

func TestProxyHealthEndpointDoesNotReachVault(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("healthz reached Vault")
	}))
	defer upstream.Close()
	handler := createProxyHandlerWithValidator(testConfig(t, upstream.URL, nil), tokenValidatorFunc(func(context.Context, string, map[string]struct{}) error {
		t.Fatal("healthz invoked token validator")
		return nil
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
}

func testConfig(t *testing.T, upstream string, routes []string) *Config {
	t.Helper()
	target, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	return &Config{
		VaultTargetURL: target,
		PublicRoutes:   routes,
		AdminEmails:    map[string]struct{}{"admin@example.com": {}},
		ListenPort:     8080,
	}
}
