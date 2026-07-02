package auth

import (
	"errors"
	"testing"

	"github.com/adnope/quiver/internal/config"
)

func TestGatewayCollectorAuthorization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		proxy       config.ProxyNetFlowConfig
		allowed     []string
		wantAllowed []string
		wantDenied  []string
	}{
		{
			name:        "legacy route fallback",
			proxy:       config.ProxyNetFlowConfig{CollectorID: "netflow-v5"},
			wantAllowed: []string{"netflow-v5"},
			wantDenied:  []string{"netflow-v9"},
		},
		{
			name: "explicit route allowlist",
			proxy: config.ProxyNetFlowConfig{Routes: []config.ProxyNetFlowRouteConfig{
				{Version: 5, CollectorID: "netflow-v5"},
				{Version: 9, CollectorID: "netflow-v9"},
			}},
			allowed:     []string{"netflow-v9"},
			wantAllowed: []string{"netflow-v9"},
			wantDenied:  []string{"netflow-v5"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.Config{
				ProxyNetFlow: tt.proxy,
				QuiverClientGateways: []config.QuiverClientGatewayConfig{{
					Name:                "gateway",
					SourceHost:          "gateway-1",
					KeyEnv:              "GATEWAY_KEY",
					AllowedCollectorIDs: tt.allowed,
				}},
			}
			authenticator, err := NewAuthenticator(cfg, func(key string) string {
				if key == "GATEWAY_KEY" {
					return "secret"
				}
				return ""
			})
			if err != nil {
				t.Fatalf("NewAuthenticator() error = %v", err)
			}
			principal, err := authenticator.Authenticate("secret")
			if err != nil {
				t.Fatalf("Authenticate() error = %v", err)
			}
			for _, collectorID := range tt.wantAllowed {
				if !principal.AllowsCollector(collectorID) {
					t.Fatalf("collector %q should be allowed", collectorID)
				}
			}
			for _, collectorID := range tt.wantDenied {
				if principal.AllowsCollector(collectorID) {
					t.Fatalf("collector %q should be denied", collectorID)
				}
			}

			delete(principal.AllowedCollectorIDs, tt.wantAllowed[0])
			fresh, err := authenticator.Authenticate("secret")
			if err != nil || !fresh.AllowsCollector(tt.wantAllowed[0]) {
				t.Fatalf("principal authorization map was not defensively copied")
			}
		})
	}
}

func TestNewAuthenticator_Errors(t *testing.T) {
	t.Parallel()

	// Nil env lookup function
	_, err := NewAuthenticator(config.Config{}, nil)
	if err == nil {
		t.Error("expected error for nil env lookup")
	}

	// Missing API key env
	cfgAPI := config.Config{}
	cfgAPI.API.Keys = []config.APIKeyConfig{{KeyEnv: "API_KEY"}}
	_, err = NewAuthenticator(cfgAPI, func(string) string { return "" })
	if err == nil {
		t.Error("expected error for missing API key env value")
	}

	// Missing REST Ingest key env
	cfgREST := config.Config{}
	cfgREST.RestIngest.APIKeys = []config.RESTAPIKeyConfig{{KeyEnv: "REST_KEY"}}
	_, err = NewAuthenticator(cfgREST, func(string) string { return "" })
	if err == nil {
		t.Error("expected error for missing REST key env value")
	}

	// Missing Gateway key env
	cfgGateway := config.Config{}
	cfgGateway.QuiverClientGateways = []config.QuiverClientGatewayConfig{{KeyEnv: "GATEWAY_KEY"}}
	_, err = NewAuthenticator(cfgGateway, func(string) string { return "" })
	if err == nil {
		t.Error("expected error for missing Gateway key env value")
	}
}

func TestAuthenticate_EdgeCases(t *testing.T) {
	t.Parallel()

	// Empty key
	auth := &Authenticator{}
	_, err := auth.Authenticate("")
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Errorf("expected ErrMissingAPIKey, got %v", err)
	}

	// Nil authenticator
	var nilAuth *Authenticator
	_, err = nilAuth.Authenticate("key")
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Errorf("expected ErrInvalidAPIKey, got %v", err)
	}

	// Invalid key
	_, err = auth.Authenticate("unknown")
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Errorf("expected ErrInvalidAPIKey, got %v", err)
	}
}

func TestPrincipal_ScopesAndAllowed(t *testing.T) {
	t.Parallel()

	// Scopes nil / not nil
	p := Principal{}
	if p.HasScope(ScopeQuery) {
		t.Error("expected HasScope to return false when Scopes is nil")
	}

	p.Scopes = map[Scope]struct{}{ScopeQuery: {}}
	if !p.HasScope(ScopeQuery) {
		t.Error("expected HasScope to return true")
	}
	if p.HasScope(ScopeIngest) {
		t.Error("expected HasScope to return false")
	}

	// AllowedCollectorIDs nil
	if p.AllowsCollector("col") {
		t.Error("expected AllowsCollector to return false when AllowedCollectorIDs is nil")
	}
}

func TestNewAuthenticator_GatewayFallback(t *testing.T) {
	t.Parallel()

	cfg := config.Config{}
	cfg.ProxyNetFlow.CollectorID = "fallback-collector"
	cfg.QuiverClientGateways = []config.QuiverClientGatewayConfig{
		{Name: "gw", KeyEnv: "GW_KEY", SourceHost: "gw-host"},
	}

	auth, err := NewAuthenticator(cfg, func(key string) string {
		if key == "GW_KEY" {
			return "gw-secret"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}

	p, err := auth.Authenticate("gw-secret")
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	if !p.AllowsCollector("fallback-collector") {
		t.Error("expected fallback collector to be allowed")
	}
}

func TestNewAuthenticator_SuccessAllKeys(t *testing.T) {
	t.Parallel()

	cfg := config.Config{}
	cfg.API.Keys = []config.APIKeyConfig{
		{Name: "admin", KeyEnv: "ADMIN_KEY", Scopes: []string{"query", "metrics"}},
	}
	cfg.RestIngest.APIKeys = []config.RESTAPIKeyConfig{
		{Name: "rest-client", KeyEnv: "REST_KEY", SourceHost: "rest-host"},
	}
	cfg.QuiverClientGateways = []config.QuiverClientGatewayConfig{
		{Name: "gw", KeyEnv: "GW_KEY", SourceHost: "gw-host", AllowedCollectorIDs: []string{"col1"}},
	}

	auth, err := NewAuthenticator(cfg, func(key string) string {
		switch key {
		case "ADMIN_KEY":
			return "admin-secret"
		case "REST_KEY":
			return "rest-secret"
		case "GW_KEY":
			return "gw-secret"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}

	// Verify all keys authenticate successfully
	pAdmin, err := auth.Authenticate("admin-secret")
	if err != nil {
		t.Fatalf("admin auth failed: %v", err)
	}
	if !pAdmin.HasScope(ScopeQuery) || !pAdmin.HasScope(ScopeMetrics) {
		t.Error("admin missing scopes")
	}

	pRest, err := auth.Authenticate("rest-secret")
	if err != nil {
		t.Fatalf("rest auth failed: %v", err)
	}
	if pRest.Name != "rest-client" || pRest.SourceHost != "rest-host" {
		t.Error("rest principal mismatch")
	}

	pGw, err := auth.Authenticate("gw-secret")
	if err != nil {
		t.Fatalf("gw auth failed: %v", err)
	}
	if !pGw.AllowsCollector("col1") {
		t.Error("gw principal mismatch")
	}
}
