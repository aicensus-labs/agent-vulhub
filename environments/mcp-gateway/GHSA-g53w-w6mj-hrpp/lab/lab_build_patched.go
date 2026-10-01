package mcprouter

// Per-variant ExtProcServer construction for the patched revision (0.7.0).
//
// In 0.7.0 the shared router key was removed from config.MCPServersConfig
// entirely: the router-key header now carries a backend-init JWT that must be
// signed by the gateway HMAC key, so the harness wires a JWTManager.

import (
	"log/slog"
	"testing"

	"github.com/Kuadrant/mcp-gateway/internal/config"
	"github.com/Kuadrant/mcp-gateway/internal/session"
)

func buildLabServer(t *testing.T, _ string, logger *slog.Logger) *ExtProcServer {
	t.Helper()
	manager, err := session.NewJWTManager(fixtureSigningKey, 0, logger, nil)
	if err != nil {
		t.Fatalf("construct JWT manager: %v", err)
	}
	return &ExtProcServer{
		RoutingConfig: &config.MCPServersConfig{
			MCPGatewayExternalHostname: fixtureGatewayHost,
			MCPGatewayInternalHostname: fixtureGatewayHost,
		},
		Logger:     logger,
		JWTManager: manager,
	}
}
