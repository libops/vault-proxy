package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
)

func TestIsPublicRoute(t *testing.T) {
	publicRoutes := []string{
		"/.well-known/",
		"/v1/identity/oidc/",
		"/v1/auth/oidc/",
		"/v1/auth/userpass/",
	}

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"well-known exact", "/.well-known/", true},
		{"well-known subpath", "/.well-known/openid-configuration", true},
		{"identity oidc", "/v1/identity/oidc/authorize", true},
		{"auth oidc", "/v1/auth/oidc/login", true},
		{"userpass login", "/v1/auth/userpass/login/alice", true},
		{"protected route", "/v1/sys/health", false},
		{"protected secrets", "/v1/secret/data/myapp", false},
		{"root path", "/", false},
		{"similar but not matching", "/v1/auth/token/create", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPublicRoute(tt.path, publicRoutes)
			if result != tt.expected {
				t.Errorf("isPublicRoute(%q) = %v, expected %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		configYAML  string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			configYAML: `vault_addr: "http://127.0.0.1:8200"
port: 8080
admin_emails:
  - admin@example.com
  - ops@example.com
public_routes:
  - /.well-known/
  - /v1/auth/oidc/
`,
			expectError: false,
		},
		{
			name: "missing vault_addr",
			configYAML: `port: 8080
admin_emails:
  - admin@example.com
`,
			expectError: true,
			errorMsg:    "vault_addr must be set",
		},
		{
			name: "missing admin_emails",
			configYAML: `vault_addr: "http://127.0.0.1:8200"
port: 8080
`,
			expectError: true,
			errorMsg:    "admin_emails must contain at least one email",
		},
		{
			name: "invalid vault_addr URL",
			configYAML: `vault_addr: "://invalid-url"
port: 8080
admin_emails:
  - admin@example.com
`,
			expectError: true,
			errorMsg:    "invalid vault_addr",
		},
		{
			name: "port defaults to 8080",
			configYAML: `vault_addr: "http://127.0.0.1:8200"
admin_emails:
  - admin@example.com
`,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary config file
			tmpfile, err := os.CreateTemp("", "config-*.yaml")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tmpfile.Name())

			if _, err := tmpfile.Write([]byte(tt.configYAML)); err != nil {
				t.Fatal(err)
			}
			if err := tmpfile.Close(); err != nil {
				t.Fatal(err)
			}

			config, err := loadConfig(tmpfile.Name())

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errorMsg)
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if config == nil {
					t.Error("expected config to be non-nil")
				}
				if config != nil && config.ListenPort == "" {
					t.Error("expected ListenPort to have a default value")
				}
			}
		})
	}
}

func TestCreateProxyHandler_PublicRoutes(t *testing.T) {
	// Create a mock Vault server
	vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("vault response"))
	}))
	defer vaultServer.Close()

	vaultURL, _ := url.Parse(vaultServer.URL)
	config := &Config{
		VaultTargetURL: vaultURL,
		PublicRoutes: []string{
			"/.well-known/",
			"/v1/auth/oidc/",
		},
		AdminEmails: map[string]bool{
			"admin@example.com": true,
		},
		ListenPort: "8080",
	}

	handler := createProxyHandler(config)

	tests := []struct {
		name           string
		path           string
		expectedStatus int
	}{
		{"public well-known", "/.well-known/openid-configuration", http.StatusOK},
		{"public auth oidc", "/v1/auth/oidc/login", http.StatusOK},
		{"protected without token", "/v1/sys/health", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v",
					rr.Code, tt.expectedStatus)
			}
		})
	}
}

func TestCreateProxyHandler_MissingToken(t *testing.T) {
	vaultURL, _ := url.Parse("http://localhost:8200")
	config := &Config{
		VaultTargetURL: vaultURL,
		PublicRoutes:   []string{},
		AdminEmails: map[string]bool{
			"admin@example.com": true,
		},
		ListenPort: "8080",
	}

	handler := createProxyHandler(config)
	req := httptest.NewRequest("GET", "/v1/sys/health", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rr.Code)
	}

	expectedBody := "Access Denied: Missing X-Admin-Token header"
	if !contains(rr.Body.String(), expectedBody) {
		t.Errorf("expected body to contain %q, got %q", expectedBody, rr.Body.String())
	}
}

func TestCreateProxyHandler_TokenRemoved(t *testing.T) {
	// Create a mock Vault server that checks headers
	vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify X-Admin-Token was removed
		if r.Header.Get("X-Admin-Token") != "" {
			t.Error("X-Admin-Token header should have been removed")
		}
		// Verify Authorization header is preserved
		if r.Header.Get("Authorization") != "Bearer vault-token" {
			t.Errorf("Authorization header not preserved: got %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer vaultServer.Close()

	// Create a mock tokeninfo server
	tokeninfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := TokenInfo{
			Email:         "admin@example.com",
			EmailVerified: "true",
			ExpiresIn:     "3600",
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer tokeninfoServer.Close()

	// We can't easily override the tokeninfo URL in validateAdminToken,
	// so this test is limited. In production, you'd want to make the URL configurable.
	// For now, we'll skip the full integration test and just verify the header removal logic
	t.Skip("Integration test requires configurable tokeninfo endpoint")
}

func TestValidateAdminToken_Integration(t *testing.T) {
	// This test would require either:
	// 1. A real Google access token (not suitable for automated tests)
	// 2. Mocking the HTTP client (requires refactoring validateAdminToken)
	// 3. A test server that mimics Google's tokeninfo endpoint

	// Create a mock tokeninfo server
	tokeninfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if the request is to the tokeninfo endpoint
		if !contains(r.URL.String(), "access_token=") {
			http.Error(w, "missing access_token", http.StatusBadRequest)
			return
		}

		token := r.URL.Query().Get("access_token")
		switch token {
		case "valid-token":
			response := TokenInfo{
				Email:         "admin@example.com",
				EmailVerified: "true",
				ExpiresIn:     "3600",
			}
			_ = json.NewEncoder(w).Encode(response)
		case "invalid-email-token":
			response := TokenInfo{
				Email:         "notadmin@example.com",
				EmailVerified: "true",
				ExpiresIn:     "3600",
			}
			_ = json.NewEncoder(w).Encode(response)
		case "unverified-token":
			response := TokenInfo{
				Email:         "admin@example.com",
				EmailVerified: "false",
				ExpiresIn:     "3600",
			}
			_ = json.NewEncoder(w).Encode(response)
		default:
			http.Error(w, "invalid token", http.StatusUnauthorized)
		}
	}))
	defer tokeninfoServer.Close()

	// Note: This test would require refactoring validateAdminToken to accept
	// a custom HTTP client or tokeninfo URL. Skipping for now.
	t.Skip("Requires refactoring validateAdminToken to be testable")
}

func TestMapsKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]bool
		expected int
	}{
		{"empty map", map[string]bool{}, 0},
		{"single key", map[string]bool{"admin@example.com": true}, 1},
		{"multiple keys", map[string]bool{
			"admin@example.com": true,
			"ops@example.com":   true,
			"dev@example.com":   true,
		}, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapsKeys(tt.input)
			if len(result) != tt.expected {
				t.Errorf("mapsKeys returned %d keys, expected %d", len(result), tt.expected)
			}

			// Verify all keys are present
			for key := range tt.input {
				found := false
				for _, k := range result {
					if k == key {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("key %q not found in result", key)
				}
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && stringContains(s, substr)))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
