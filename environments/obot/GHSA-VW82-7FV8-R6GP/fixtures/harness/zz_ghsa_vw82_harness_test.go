// Harness for GHSA-VW82-7FV8-R6GP. This file is placed unchanged into the
// pinned upstream tree at pkg/api/authz/ and compiles against both revisions.
// It builds the authorizer exactly as the upstream tests do and calls the
// pinned Authorize() implementation for every case in the fixture.
package authz

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/accesscontrolrule"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	storagescheme "github.com/obot-platform/obot/pkg/storage/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	gocache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type harnessFixture struct {
	Users             map[string]harnessUser    `json:"users"`
	MCPServers        []harnessMCPServer        `json:"mcp_servers"`
	MCPServerInstance []harnessMCPServerInst    `json:"mcp_server_instances"`
	ACRs              []harnessACR              `json:"access_control_rules"`
	Cases             []harnessCase             `json:"cases"`
}

type harnessUser struct {
	Name   string   `json:"name"`
	UID    string   `json:"uid"`
	Groups []string `json:"groups"`
}

type harnessMCPServer struct {
	Name         string `json:"name"`
	Namespace    string `json:"namespace"`
	MCPCatalogID string `json:"mcp_catalog_id"`
	UserID       string `json:"user_id"`
}

type harnessMCPServerInst struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	UserID    string `json:"user_id"`
}

type harnessACR struct {
	Name         string            `json:"name"`
	Namespace    string            `json:"namespace"`
	MCPCatalogID string            `json:"mcp_catalog_id"`
	Subjects     []harnessSubject  `json:"subjects"`
	Resources    []harnessResource `json:"resources"`
}

type harnessSubject struct {
	Type types.SubjectType `json:"type"`
	ID   string            `json:"id"`
}

type harnessResource struct {
	Type types.ResourceType `json:"type"`
	ID   string             `json:"id"`
}

type harnessCase struct {
	ID              string `json:"id"`
	Path            string `json:"path"`
	Method          string `json:"method"`
	User            string `json:"user"`
	ExpectedAllowed bool   `json:"expected_allowed"`
}

type harnessResult struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	Method string `json:"method"`
	User   string `json:"user"`
	UID    string `json:"uid"`

	ExpectedAllowed bool   `json:"expected_allowed"`
	Allowed         bool   `json:"allowed"`
	Matches         bool   `json:"matches_expectation"`
	Error           string `json:"error,omitempty"`
}

type harnessReport struct {
	SchemaVersion int             `json:"schema_version"`
	Variant       string          `json:"variant"`
	Scenario      string          `json:"scenario"`
	Commit        string          `json:"commit"`
	Cases         []harnessResult `json:"cases"`
	AllMatch      bool            `json:"all_match"`
}

// TestGeneratorHarness drives the pinned Authorizer.Authorize implementation
// with the fixture's users and stored objects. It always exits successfully;
// the verdict lives in the JSON report so that a denial is a completed
// execution rather than a test failure.
func TestGeneratorHarness(t *testing.T) {
	fixturePath := os.Getenv("LAB_HARNESS_FIXTURE")
	outputPath := os.Getenv("LAB_HARNESS_OUTPUT")
	if fixturePath == "" || outputPath == "" {
		t.Fatal("LAB_HARNESS_FIXTURE and LAB_HARNESS_OUTPUT must be set")
	}

	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture harnessFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	objects := make([]client.Object, 0, len(fixture.MCPServers)+len(fixture.MCPServerInstance))
	for _, server := range fixture.MCPServers {
		objects = append(objects, &v1.MCPServer{
			ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace},
			Spec: v1.MCPServerSpec{
				MCPCatalogID: server.MCPCatalogID,
				UserID:       server.UserID,
			},
		})
	}
	for _, instance := range fixture.MCPServerInstance {
		objects = append(objects, &v1.MCPServerInstance{
			ObjectMeta: metav1.ObjectMeta{Name: instance.Name, Namespace: instance.Namespace},
			Spec:       v1.MCPServerInstanceSpec{UserID: instance.UserID},
		})
	}

	storage := clientfake.NewClientBuilder().
		WithScheme(storagescheme.Scheme).
		WithObjects(objects...).
		Build()

	indexer := gocache.NewIndexer(gocache.MetaNamespaceKeyFunc, gocache.Indexers{
		"user-ids": func(obj any) ([]string, error) {
			acr, ok := obj.(*v1.AccessControlRule)
			if !ok {
				return nil, nil
			}
			var results []string
			for _, subject := range acr.Spec.Manifest.Subjects {
				if subject.Type == types.SubjectTypeUser {
					results = append(results, subject.ID)
				}
			}
			return results, nil
		},
		"catalog-entry-names": func(obj any) ([]string, error) {
			acr, ok := obj.(*v1.AccessControlRule)
			if !ok {
				return nil, nil
			}
			var results []string
			for _, resource := range acr.Spec.Manifest.Resources {
				if resource.Type == types.ResourceTypeMCPServerCatalogEntry {
					results = append(results, resource.ID)
				}
			}
			return results, nil
		},
		"server-names": func(obj any) ([]string, error) {
			acr, ok := obj.(*v1.AccessControlRule)
			if !ok {
				return nil, nil
			}
			var results []string
			for _, resource := range acr.Spec.Manifest.Resources {
				if resource.Type == types.ResourceTypeMCPServer {
					results = append(results, resource.ID)
				}
			}
			return results, nil
		},
		"selectors": func(obj any) ([]string, error) {
			acr, ok := obj.(*v1.AccessControlRule)
			if !ok {
				return nil, nil
			}
			var results []string
			for _, resource := range acr.Spec.Manifest.Resources {
				if resource.Type == types.ResourceTypeSelector {
					results = append(results, resource.ID)
				}
			}
			return results, nil
		},
	})

	for index := range fixture.ACRs {
		rule := fixture.ACRs[index]
		acr := &v1.AccessControlRule{
			ObjectMeta: metav1.ObjectMeta{Name: rule.Name, Namespace: rule.Namespace},
			Spec: v1.AccessControlRuleSpec{
				MCPCatalogID: rule.MCPCatalogID,
				Manifest: types.AccessControlRuleManifest{
					Subjects:  make([]types.Subject, 0, len(rule.Subjects)),
					Resources: make([]types.Resource, 0, len(rule.Resources)),
				},
			},
		}
		for _, subject := range rule.Subjects {
			acr.Spec.Manifest.Subjects = append(acr.Spec.Manifest.Subjects, types.Subject{Type: subject.Type, ID: subject.ID})
		}
		for _, resource := range rule.Resources {
			acr.Spec.Manifest.Resources = append(acr.Spec.Manifest.Resources, types.Resource{Type: resource.Type, ID: resource.ID})
		}
		if err := indexer.Add(acr); err != nil {
			t.Fatalf("index access control rule %s: %v", rule.Name, err)
		}
	}

	authorizer := NewAuthorizer(storage, storage, false, accesscontrolrule.NewAccessControlRuleHelper(indexer, storage), false)

	report := harnessReport{
		SchemaVersion: 1,
		Variant:       os.Getenv("LAB_VARIANT"),
		Scenario:      os.Getenv("LAB_SCENARIO"),
		Commit:        os.Getenv("LAB_COMMIT"),
		Cases:         make([]harnessResult, 0, len(fixture.Cases)),
	}
	allMatch := true
	for _, item := range fixture.Cases {
		identity, ok := fixture.Users[item.User]
		if !ok {
			t.Fatalf("case %s references unknown fixture user %q", item.ID, item.User)
		}
		req := httptest.NewRequest(item.Method, item.Path, nil)
		allowed := authorizer.Authorize(req, &user.DefaultInfo{
			Name:   identity.Name,
			UID:    identity.UID,
			Groups: identity.Groups,
		})
		result := harnessResult{
			ID:              item.ID,
			Path:            item.Path,
			Method:          item.Method,
			User:            item.User,
			UID:             identity.UID,
			ExpectedAllowed: item.ExpectedAllowed,
			Allowed:         allowed,
			Matches:         allowed == item.ExpectedAllowed,
		}
		if !result.Matches {
			allMatch = false
		}
		report.Cases = append(report.Cases, result)
		t.Run(sanitizeSubtest(item.ID), func(t *testing.T) {
			t.Logf("authorize %s %s user=%s allowed=%v expected=%v",
				item.Method, item.Path, identity.UID, allowed, item.ExpectedAllowed)
		})
	}
	report.AllMatch = allMatch

	if err := os.MkdirAll(outputPath, 0o755); err != nil {
		t.Fatalf("create report directory: %v", err)
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("encode report: %v", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(filepath.Join(outputPath, "authorize-report.json"), encoded, 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	fmt.Printf("harness: variant=%s scenario=%s all_match=%v\n", report.Variant, report.Scenario, report.AllMatch)
}

func sanitizeSubtest(name string) string {
	out := make([]rune, 0, len(name))
	for _, char := range name {
		if char == '/' || char == ' ' {
			out = append(out, '_')
			continue
		}
		out = append(out, char)
	}
	return string(out)
}
