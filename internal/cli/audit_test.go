package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditExportFollowsPagesAndPreservesFilters(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/admin/v1/orgs/acme/audit-events" || r.Header.Get("Authorization") != "Bearer fixture" || r.URL.Query().Get("q") != "policy & report" || r.URL.Query().Get("outcome") != "denied" || r.URL.Query().Get("limit") != "1" {
			t.Errorf("request %s", r.URL)
		}
		if calls == 1 {
			if r.URL.Query().Get("cursor") != "" {
				t.Error("unexpected initial cursor")
			}
			_, _ = w.Write([]byte(`{"data":[{"id":"first"}],"nextCursor":"opaque+/= cursor","coverage":"Observed only"}`))
		} else {
			if r.URL.Query().Get("cursor") != "opaque+/= cursor" {
				t.Error("cursor was not preserved")
			}
			_, _ = w.Write([]byte(`{"data":[{"id":"second"}],"nextCursor":null,"coverage":"Observed only"}`))
		}
	}))
	defer srv.Close()
	out := filepath.Join(t.TempDir(), "audit.json")
	code, stdout, stderr := run(t, "--base-url", srv.URL, "--api-key", "fixture", "admin", "export-audit-events", "--org-slug", "acme", "--q", "policy & report", "--outcome", "denied", "--limit", "1", "--all", "--out", out)
	if code != 0 || stdout != "" {
		t.Fatalf("exit %d stdout %q stderr %s", code, stdout, stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Data []struct {
			ID string `json:"id"`
		}
		NextCursor *string
		Coverage   string
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(result.Data) != 2 || result.Data[0].ID != "first" || result.Data[1].ID != "second" || result.NextCursor != nil || result.Coverage != "Observed only" {
		t.Fatalf("calls %d result %s", calls, data)
	}
}

func TestAllPagesFailsWithoutOverwritingOutput(t *testing.T) {
	for _, scenario := range []string{"repeated cursor", "failed page", "missing cursor", "invalid array"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				switch {
				case scenario == "missing cursor":
					_, _ = w.Write([]byte(`{"data":[]}`))
				case scenario == "invalid array":
					_, _ = w.Write([]byte(`{"data":null,"nextCursor":null}`))
				case scenario == "failed page" && calls == 2:
					w.WriteHeader(503)
					_, _ = w.Write([]byte(`{"error":"unavailable"}`))
				default:
					_, _ = w.Write([]byte(`{"data":[{"id":"one"}],"nextCursor":"repeat"}`))
				}
			}))
			defer srv.Close()
			out := filepath.Join(t.TempDir(), "existing.json")
			if err := os.WriteFile(out, []byte("existing"), 0600); err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := run(t, "--base-url", srv.URL, "--api-key", "fixture", "admin", "export-audit-events", "--org-slug", "acme", "--all", "--out", out)
			data, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if code != 1 || stdout != "" || string(data) != "existing" || stderr == "" || calls > 2 {
				t.Fatalf("exit %d calls %d data %s stderr %s", code, calls, data, stderr)
			}
		})
	}
}

func TestAuditDefaultPreservesJSONBytes(t *testing.T) {
	const response = "{\n  \"data\": [],\n  \"nextCursor\": \"more\"\n}\n"
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; _, _ = w.Write([]byte(response)) }))
	defer srv.Close()
	code, stdout, stderr := run(t, "--base-url", srv.URL, "--api-key", "fixture", "admin", "export-audit-events", "--org-slug", "acme")
	if code != 0 || stdout != response || calls != 1 {
		t.Fatalf("exit %d calls %d stdout %q stderr %s", code, calls, stdout, stderr)
	}
	code, stdout, stderr = run(t, "admin", "export-audit-events", "--help")
	if code != 0 || !strings.Contains(stdout, "--all") || !strings.Contains(stdout, "--outcome") || !strings.Contains(stdout, "--cursor") {
		t.Fatalf("help: %s %s", stdout, stderr)
	}
	code, stdout, _ = run(t, "consumer", "--help")
	if code != 0 || !strings.Contains(stdout, "export-audit-events") {
		t.Fatal("Consumer help must expose party-scoped audit events")
	}
}
