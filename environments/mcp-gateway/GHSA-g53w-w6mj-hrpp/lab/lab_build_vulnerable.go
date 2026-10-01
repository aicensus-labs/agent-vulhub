package mcprouter

// Per-variant ExtProcServer construction for the vulnerable revision (0.6.0).
//
// In 0.6.0 the hair-pin path authenticates the caller by comparing the router-key
// header against config.MCPServersConfig.RouterAPIKey, a shared secret. There is
// no JWTManager field on ExtProcServer in this revision, so the harness wires the
// shared key and nothing else.

import (
	"log/slog"
	"testing"

	"github.com/Kuadrant/mcp-gateway/internal/config"
)

func buildLabServer(t *testing.T, _ string, logger *slog.Logger) *ExtProcServer {
	t.Helper()
	return &ExtProcServer{
		RoutingConfig: &config.MCPServersConfig{
			MCPGatewayExternalHostname: fixtureGatewayHost,
			MCPGatewayInternalHostname: fixtureGatewayHost,
			RouterAPIKey:               fixtureRouterKey,
		},
		Logger: logger,
	}
}
