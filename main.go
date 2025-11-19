package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// YAMLConfig represents the structure of the YAML configuration file.
type YAMLConfig struct {
	VaultAddr    string   `yaml:"vault_addr"`
	Port         int      `yaml:"port"`
	AdminEmails  []string `yaml:"admin_emails"`
	PublicRoutes []string `yaml:"public_routes"`
}

// Config holds all configuration for the proxy, loaded from YAML.
type Config struct {
	VaultTargetURL *url.URL
	PublicRoutes   []string
	AdminEmails    map[string]bool // Use a map for fast O(1) lookups
	ListenPort     string
}

// loadYAMLConfig loads configuration from a YAML file or VAULT_PROXY_YAML env var.
func loadYAMLConfig(configPath string) (*YAMLConfig, error) {
	var data []byte
	var err error

	// Check for VAULT_PROXY_YAML environment variable first
	if yamlEnv := os.Getenv("VAULT_PROXY_YAML"); yamlEnv != "" {
		data = []byte(yamlEnv)
	} else if configPath != "" {
		data, err = os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	} else {
		return nil, fmt.Errorf("either VAULT_PROXY_YAML environment variable or -config flag must be set")
	}

	var yamlConfig YAMLConfig
	if err := yaml.Unmarshal(data, &yamlConfig); err != nil {
		return nil, fmt.Errorf("failed to parse YAML config: %w", err)
	}

	return &yamlConfig, nil
}

// loadConfig loads configuration from YAML file or VAULT_PROXY_YAML env var.
func loadConfig(configPath string) (*Config, error) {
	yamlConfig, err := loadYAMLConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load YAML config: %w", err)
	}

	// Validate required fields
	if yamlConfig.VaultAddr == "" {
		return nil, fmt.Errorf("vault_addr must be set in config file")
	}
	targetURL, err := url.Parse(yamlConfig.VaultAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid vault_addr: %w", err)
	}

	if len(yamlConfig.AdminEmails) == 0 {
		return nil, fmt.Errorf("admin_emails must contain at least one email")
	}

	// Convert admin emails list to map for O(1) lookups
	adminEmails := make(map[string]bool)
	for _, email := range yamlConfig.AdminEmails {
		if email != "" {
			adminEmails[strings.TrimSpace(email)] = true
		}
	}

	port := yamlConfig.Port
	if port == 0 {
		port = 8080
	}

	return &Config{
		VaultTargetURL: targetURL,
		PublicRoutes:   yamlConfig.PublicRoutes,
		AdminEmails:    adminEmails,
		ListenPort:     fmt.Sprintf("%d", port),
	}, nil
}

// isPublicRoute checks if a given request path matches any of the public route prefixes.
func isPublicRoute(path string, publicRoutes []string) bool {
	for _, route := range publicRoutes {
		if strings.HasPrefix(path, route) {
			return true
		}
	}
	return false
}

// TokenInfo represents the response from Google's tokeninfo endpoint.
type TokenInfo struct {
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	ExpiresIn     string `json:"expires_in"`
	Scope         string `json:"scope"`
}

// validateAdminToken validates a Google OAuth 2.0 access token.
// It calls Google's tokeninfo endpoint to verify the token and extract email.
func validateAdminToken(ctx context.Context, tokenString string, adminEmails map[string]bool) (bool, error) {
	// Call Google's tokeninfo endpoint to validate the access token
	tokenInfoURL := "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=" + url.QueryEscape(tokenString)

	req, err := http.NewRequestWithContext(ctx, "GET", tokenInfoURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create tokeninfo request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to call tokeninfo endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("tokeninfo returned status %d", resp.StatusCode)
	}

	var tokenInfo TokenInfo
	if err := json.NewDecoder(resp.Body).Decode(&tokenInfo); err != nil {
		return false, fmt.Errorf("failed to parse tokeninfo response: %w", err)
	}
	if tokenInfo.EmailVerified != "true" {
		return false, fmt.Errorf("email not verified")
	}
	if _, isAdmin := adminEmails[tokenInfo.Email]; !isAdmin {
		return false, fmt.Errorf("non-admin hitting protected route")
	}

	return true, nil
}

// createProxyHandler creates the main HTTP handler for the proxy.
func createProxyHandler(config *Config) http.Handler {
	// Create the reverse proxy that will forward to Vault
	proxy := httputil.NewSingleHostReverseProxy(config.VaultTargetURL)

	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = config.VaultTargetURL.Scheme
		req.URL.Host = config.VaultTargetURL.Host
		req.Host = config.VaultTargetURL.Host
	}

	// Return the main handler function
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicRoute(r.URL.Path, config.PublicRoutes) {
			slog.Info(r.Method, "path", r.URL.Path)
			proxy.ServeHTTP(w, r)
			return
		}

		token := r.Header.Get("X-Admin-Token")
		if token == "" {
			slog.Warn("access denied: missing header", "path", r.URL.Path, "status", 401)
			http.Error(w, "Access Denied: Missing X-Admin-Token header", http.StatusUnauthorized)
			return
		}

		isValid, err := validateAdminToken(r.Context(), token, config.AdminEmails)
		if err != nil {
			slog.Warn("access denied: token validation error", "path", r.URL.Path, "error", err, "status", 401)
			http.Error(w, fmt.Sprintf("Token Validation Error: %v", err), http.StatusUnauthorized)
			return
		}

		if !isValid {
			slog.Warn("access denied: user not admin", "path", r.URL.Path, "status", 403)
			http.Error(w, "Access Denied: User is not an admin", http.StatusForbidden)
			return
		}

		r.Header.Del("X-Admin-Token")

		// Forward the request to Vault
		proxy.ServeHTTP(w, r)
	})
}

func main() {
	// Parse command-line flags
	configPath := flag.String("config", "", "Path to YAML configuration file (optional if VAULT_PROXY_YAML is set)")
	flag.Parse()

	// Load configuration from YAML file or VAULT_PROXY_YAML env var
	config, err := loadConfig(*configPath)
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	slog.Info("starting vault proxy",
		"port", config.ListenPort,
		"vault_addr", config.VaultTargetURL.String(),
		"admin_emails", mapsKeys(config.AdminEmails),
		"public_routes", config.PublicRoutes)

	// Create the handler and start the server
	handler := createProxyHandler(config)
	if err := http.ListenAndServe(":"+config.ListenPort, handler); err != nil {
		slog.Error("failed to start server", "error", err)
		os.Exit(1)
	}
}

// Helper function to get keys from a map for logging
func mapsKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
