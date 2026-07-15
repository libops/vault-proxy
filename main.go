package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/mail"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultListenPort = 8080
	// #nosec G101 -- this is Google's public token-inspection endpoint, not a credential.
	defaultTokenInfoURL = "https://oauth2.googleapis.com/tokeninfo"
	maxTokenInfoBody    = 1 << 20
)

// YAMLConfig represents the supported configuration file fields.
type YAMLConfig struct {
	VaultAddr    string   `yaml:"vault_addr"`
	Port         int      `yaml:"port"`
	AdminEmails  []string `yaml:"admin_emails"`
	PublicRoutes []string `yaml:"public_routes"`
}

// Config is the validated runtime configuration.
type Config struct {
	VaultTargetURL *url.URL
	PublicRoutes   []string
	AdminEmails    map[string]struct{}
	ListenPort     int
}

// TokenInfo is the subset of Google's tokeninfo response used for access
// control. Google rejects expired or invalid access tokens before returning it.
type TokenInfo struct {
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
}

type tokenValidator interface {
	Validate(context.Context, string, map[string]struct{}) error
}

type googleTokenValidator struct {
	client   *http.Client
	endpoint string
}

func loadYAMLConfig(configPath string) (*YAMLConfig, error) {
	var data []byte
	var err error

	if yamlEnv := os.Getenv("VAULT_PROXY_YAML"); yamlEnv != "" {
		data = []byte(yamlEnv)
	} else if configPath != "" {
		// #nosec G304 -- the operator explicitly selects the configuration path;
		// the process runs non-root and the container filesystem is read-only.
		data, err = os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("read config file: %w", err)
		}
	} else {
		return nil, errors.New("either VAULT_PROXY_YAML or -config must be set")
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var config YAMLConfig
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("parse YAML config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("parse YAML config: multiple documents are not allowed")
		}
		return nil, fmt.Errorf("parse YAML config: %w", err)
	}
	return &config, nil
}

func loadConfig(configPath string) (*Config, error) {
	yamlConfig, err := loadYAMLConfig(configPath)
	if err != nil {
		return nil, err
	}

	targetURL, err := validateVaultURL(yamlConfig.VaultAddr)
	if err != nil {
		return nil, err
	}

	adminEmails := make(map[string]struct{}, len(yamlConfig.AdminEmails))
	for _, configuredEmail := range yamlConfig.AdminEmails {
		email := normalizeEmail(configuredEmail)
		parsed, parseErr := mail.ParseAddress(email)
		if email == "" || parseErr != nil || normalizeEmail(parsed.Address) != email {
			return nil, fmt.Errorf("invalid admin email %q", configuredEmail)
		}
		adminEmails[email] = struct{}{}
	}
	if len(adminEmails) == 0 {
		return nil, errors.New("admin_emails must contain at least one valid email")
	}

	for _, route := range yamlConfig.PublicRoutes {
		if err := validatePublicRoutePattern(route); err != nil {
			return nil, err
		}
	}

	port := yamlConfig.Port
	if port == 0 {
		port = defaultListenPort
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port must be between 1 and 65535, got %d", port)
	}

	return &Config{
		VaultTargetURL: targetURL,
		PublicRoutes:   append([]string(nil), yamlConfig.PublicRoutes...),
		AdminEmails:    adminEmails,
		ListenPort:     port,
	}, nil
}

func validateVaultURL(rawURL string) (*url.URL, error) {
	if strings.TrimSpace(rawURL) != rawURL || rawURL == "" {
		return nil, errors.New("vault_addr must be a non-empty absolute URL")
	}
	targetURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid vault_addr: %w", err)
	}
	if (targetURL.Scheme != "http" && targetURL.Scheme != "https") || targetURL.Host == "" {
		return nil, errors.New("vault_addr must use http or https and include a host")
	}
	if targetURL.User != nil || targetURL.RawQuery != "" || targetURL.Fragment != "" {
		return nil, errors.New("vault_addr must not contain credentials, a query, or a fragment")
	}
	if targetURL.Path != "" && targetURL.Path != "/" {
		return nil, errors.New("vault_addr must not contain a path")
	}
	return targetURL, nil
}

// Public route patterns are deliberately narrower than the legacy prefix
// rules. A literal path is exact, '*' matches one complete path segment, and a
// final '/**' matches the named subtree. Other wildcard forms are rejected.
func validatePublicRoutePattern(pattern string) error {
	if pattern == "" || !strings.HasPrefix(pattern, "/") || pattern != path.Clean(pattern) {
		return fmt.Errorf("public route %q must be a canonical absolute path", pattern)
	}
	segments := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	for i, segment := range segments {
		if segment == "**" {
			if i != len(segments)-1 || i == 0 {
				return fmt.Errorf("public route %q may use ** only as its final segment", pattern)
			}
			continue
		}
		if segment == "*" {
			continue
		}
		if segment == "" || strings.ContainsAny(segment, "*?[]\\") {
			return fmt.Errorf("public route %q contains an invalid segment", pattern)
		}
	}
	return nil
}

func isPublicRoute(requestPath string, publicRoutes []string) bool {
	if requestPath == "" || requestPath != path.Clean(requestPath) {
		return false
	}
	for _, pattern := range publicRoutes {
		if strings.HasSuffix(pattern, "/**") {
			base := strings.TrimSuffix(pattern, "/**")
			if requestPath == base || strings.HasPrefix(requestPath, base+"/") {
				return true
			}
			continue
		}
		matched, err := path.Match(pattern, requestPath)
		if err == nil && matched {
			return true
		}
	}
	return false
}

func (validator googleTokenValidator) Validate(ctx context.Context, token string, adminEmails map[string]struct{}) error {
	if token == "" {
		return errors.New("admin token missing")
	}
	endpoint, err := url.Parse(validator.endpoint)
	if err != nil {
		return errors.New("token validator is misconfigured")
	}
	query := endpoint.Query()
	query.Set("access_token", token)
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		// The parsed URL contains the access token as a query parameter. Do not
		// wrap errors that can reproduce that URL in their text.
		return errors.New("create tokeninfo request failed")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := validator.client.Do(req)
	if err != nil {
		// http.Client errors commonly include the complete request URL. Returning
		// the transport error would make the Google credential loggable by the
		// caller because tokeninfo receives it in the query string.
		return errors.New("tokeninfo request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("tokeninfo rejected token with status %d", resp.StatusCode)
	}

	var tokenInfo TokenInfo
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxTokenInfoBody))
	if err := decoder.Decode(&tokenInfo); err != nil {
		return fmt.Errorf("parse tokeninfo response: %w", err)
	}
	return validateAdminIdentity(tokenInfo, adminEmails)
}

func validateAdminIdentity(tokenInfo TokenInfo, adminEmails map[string]struct{}) error {
	email := normalizeEmail(tokenInfo.Email)
	if email == "" {
		return errors.New("token email missing")
	}
	if _, isAdmin := adminEmails[email]; !isAdmin {
		return errors.New("token identity is not an administrator")
	}
	verified, err := strconv.ParseBool(tokenInfo.EmailVerified)
	if err != nil || !verified {
		return errors.New("token email is not verified")
	}
	return nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func createProxyHandler(config *Config) http.Handler {
	validator := googleTokenValidator{
		client:   &http.Client{Timeout: 10 * time.Second},
		endpoint: defaultTokenInfoURL,
	}
	return createProxyHandlerWithValidator(config, validator)
}

func createProxyHandlerWithValidator(config *Config, validator tokenValidator) http.Handler {
	proxy := &httputil.ReverseProxy{}
	proxy.Rewrite = func(request *httputil.ProxyRequest) {
		// Rewrite mode removes the standard client-provided Forwarded and
		// X-Forwarded-* values before this function runs. Remove extensions as
		// well and do not reconstruct them: Vault must not make authorization or
		// audit decisions using an attacker-supplied client IP, host, or scheme.
		for header := range request.Out.Header {
			normalized := strings.ToLower(header)
			if normalized == "forwarded" || normalized == "x-real-ip" || strings.HasPrefix(normalized, "x-forwarded-") {
				request.Out.Header.Del(header)
			}
		}
		request.SetURL(config.VaultTargetURL)
		request.Out.Host = request.Out.URL.Host
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		slog.Error("vault upstream request failed", "error", err)
		http.Error(w, "Vault upstream unavailable", http.StatusBadGateway)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Capture and remove the proxy credential before every forwarding path,
		// including public routes. Vault must never receive this Google token.
		token := r.Header.Get("X-Admin-Token")
		r.Header.Del("X-Admin-Token")

		if isPublicRoute(r.URL.Path, config.PublicRoutes) {
			slog.Info("forwarding public Vault route", "method", r.Method, "path", r.URL.Path)
			proxy.ServeHTTP(w, r)
			return
		}
		if token == "" {
			slog.Warn("protected Vault route denied", "path", r.URL.Path, "reason", "missing admin token")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if err := validator.Validate(r.Context(), token, config.AdminEmails); err != nil {
			// Validator errors are intentionally not logged. A transport error may
			// contain a token-bearing request URL, and authentication details are not
			// needed to record the denied path.
			slog.Warn("protected Vault route denied", "path", r.URL.Path, "reason", "token validation failed")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}

func main() {
	configPath := flag.String("config", "", "path to YAML configuration (optional when VAULT_PROXY_YAML is set)")
	flag.Parse()

	config, err := loadConfig(*configPath)
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", config.ListenPort),
		Handler:           createProxyHandler(config),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       90 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serverErrors := make(chan error, 1)
	go func() {
		slog.Info("starting vault proxy", "port", config.ListenPort, "vault_addr", config.VaultTargetURL.Redacted(), "admin_count", len(config.AdminEmails), "public_routes", config.PublicRoutes)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Error("vault proxy stopped", "error", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("vault proxy shutdown failed", "error", err)
			os.Exit(1)
		}
	}
}
