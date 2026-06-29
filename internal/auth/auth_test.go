package auth

import (
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
