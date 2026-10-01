package mcprouter

// Shared mechanism harness for GHSA-g53w-w6mj-hrpp.
//
// It calls the upstream ExtProcServer.HandleNoneToolCall method directly with a
// fixed synthetic request. No HTTP server, Envoy, or Kubernetes control plane is
// involved: the hair-pin decision is a pure function of the request headers and
// the router configuration, so the real upstream code is exercised in-process.
//
// The harness never decides whether the behaviour is a vulnerability; it only
// records what the upstream code did. verify.py makes the judgement.
//
// The per-variant ExtProcServer construction lives in lab_build_vulnerable.go
// and lab_build_patched.go, because the two revisions disagree on where the
// router key is configured and only 0.7.0 has a JWTManager field at all.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	eppb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typepb "github.com/envoyproxy/go-control-plane/envoy/type/v3"
)

const (
	fixtureRouterKey    = "shared-router-key-value"
	fixtureSigningKey   = "synthetic-gateway-hmac-signing-key"
	fixtureGatewayHost  = "gateway.example.invalid"
	scenarioAttack      = "attack"
	scenarioBenign      = "benign"
	variantVulnerable   = "vulnerable"
	variantPatched      = "patched"
)

type fixtureRequest struct {
	Description string            `json:"description"`
	Method      string            `json:"method"`
	Params      map[string]any    `json:"params"`
	Headers     map[string]string `json:"headers"`
}

type observation struct {
	SchemaVersion int               `json:"schema_version"`
	Context       observationCtx    `json:"context"`
	TargetReady   bool              `json:"target_ready"`
	Request       map[string]any    `json:"request"`
	Response      map[string]any    `json:"response"`
	HeaderRewrite map[string]string `json:"header_rewrite"`
	Error         string            `json:"error,omitempty"`
}

type observationCtx struct {
	SchemaVersion int    `json:"schema_version"`
	RunID         string `json:"run_id"`
	CaseID        string `json:"case_id"`
	Variant       string `json:"variant"`
	Scenario      string `json:"scenario"`
}

type labContext struct {
	SchemaVersion int    `json:"schema_version"`
	RunID         string `json:"run_id"`
	CaseID        string `json:"case_id"`
	Variant       string `json:"variant"`
	Scenario      string `json:"scenario"`
}

func labLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestMechanismHairpinInitialize(t *testing.T) {
	contextPath := os.Getenv("LAB_CONTEXT")
	outputDir := os.Getenv("LAB_OUTPUT")
	fixturesDir := os.Getenv("LAB_FIXTURES")
	if contextPath == "" || outputDir == "" || fixturesDir == "" {
		t.Fatalf("LAB_CONTEXT, LAB_OUTPUT and LAB_FIXTURES must be set")
	}

	var lab labContext
	readJSONFile(t, contextPath, &lab)
	if lab.Variant != variantVulnerable && lab.Variant != variantPatched {
		t.Fatalf("unexpected variant %q", lab.Variant)
	}

	fixtureName := "benign.json"
	if lab.Scenario == scenarioAttack {
		fixtureName = "attack.json"
	}
	var fixture fixtureRequest
	readJSONFile(t, filepath.Join(fixturesDir, fixtureName), &fixture)

	server := buildLabServer(t, lab.Variant, labLogger())

	headerValues := make([]*corev3.HeaderValue, 0, len(fixture.Headers))
	for key, value := range fixture.Headers {
		headerValues = append(headerValues, &corev3.HeaderValue{Key: key, RawValue: []byte(value)})
	}
	mcpReq := &MCPRequest{
		ID:      1,
		JSONRPC: "2.0",
		Method:  fixture.Method,
		Params:  fixture.Params,
		Headers: &corev3.HeaderMap{Headers: headerValues},
	}

	record := observation{
		SchemaVersion: 1,
		Context: observationCtx{
			SchemaVersion: lab.SchemaVersion, RunID: lab.RunID, CaseID: lab.CaseID,
			Variant: lab.Variant, Scenario: lab.Scenario,
		},
		Request: map[string]any{
			"method":  fixture.Method,
			"headers": fixture.Headers,
		},
		HeaderRewrite: map[string]string{},
	}

	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				record.Error = fmt.Sprintf("panic: %v", recovered)
			}
		}()
		responses := server.HandleNoneToolCall(context.Background(), mcpReq)
		record.TargetReady = true
		record.Response = summariseResponses(responses)
		record.HeaderRewrite = extractHeaderRewrite(responses)
	}()

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		t.Fatalf("create output dir: %v", err)
	}
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatalf("encode observation: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "observation.json"), append(encoded, '\n'), 0o644); err != nil {
		t.Fatalf("write observation: %v", err)
	}
}

// summariseResponses reduces the ext-proc response into JSON-safe facts.
func summariseResponses(responses []*eppb.ProcessingResponse) map[string]any {
	summary := map[string]any{"count": len(responses)}
	for _, response := range responses {
		if immediate := response.GetImmediateResponse(); immediate != nil {
			summary["kind"] = "immediate_response"
			summary["immediate_code"] = int32(immediate.GetStatus().GetCode())
			summary["immediate_status"] = typepb.StatusCode_name[int32(immediate.GetStatus().GetCode())]
			summary["immediate_body"] = string(immediate.GetBody())
			return summary
		}
		if body := response.GetRequestBody(); body != nil && body.GetResponse() != nil {
			summary["kind"] = "request_body_mutation"
			summary["clear_route_cache"] = body.GetResponse().GetClearRouteCache()
			return summary
		}
	}
	summary["kind"] = "other"
	return summary
}

// extractHeaderRewrite reports the headers the router asked Envoy to set and
// remove, which is where the authority rewrite becomes observable.
func extractHeaderRewrite(responses []*eppb.ProcessingResponse) map[string]string {
	rewrite := map[string]string{}
	for _, response := range responses {
		body := response.GetRequestBody()
		if body == nil || body.GetResponse() == nil {
			continue
		}
		mutation := body.GetResponse().GetHeaderMutation()
		if mutation == nil {
			continue
		}
		for _, option := range mutation.GetSetHeaders() {
			header := option.GetHeader()
			if header == nil {
				continue
			}
			rewrite[header.GetKey()] = string(header.GetRawValue())
		}
		for _, removed := range mutation.GetRemoveHeaders() {
			rewrite["-"+removed] = ""
		}
	}
	return rewrite
}

func readJSONFile(t *testing.T, path string, target any) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(content, target); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}
