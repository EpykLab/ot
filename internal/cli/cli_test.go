package cli

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func executeIn(stdin string, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := Execute(args, strings.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func execute(args ...string) (int, string, string) {
	return executeIn("", args...)
}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ot-empty-config")
	if err != nil {
		panic(err)
	}
	os.Setenv("XDG_CONFIG_HOME", dir)
	os.Setenv("OPENTRUST_ORG_SLUG", "")
	os.Setenv("OPENTRUST_OFFERING_SLUG", "")
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	t.Setenv("OPENTRUST_API_KEY", "")
	t.Setenv("OPENTRUST_BASE_URL", "")
	t.Setenv("OPENTRUST_ORG_SLUG", "")
	t.Setenv("OPENTRUST_OFFERING_SLUG", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	return execute(args...)
}

type operationCall struct {
	audience string
	command  string
	args     []string
	method   string
	path     string
	query    url.Values
	key      string
	body     string
	fileName string
	fileBody string
	form     map[string]string
}

func operationCalls() []operationCall {
	page := url.Values{"limit": {"2"}, "cursor": {"next"}}
	pageArgs := []string{"--limit", "2", "--cursor", "next"}
	vulnQuery := url.Values{
		"limit":        {"25"},
		"cursor":       {"cur"},
		"severity":     {"high"},
		"status":       {"open"},
		"source":       {"scanner"},
		"updatedSince": {"2026-01-02T03:04:05Z"},
	}
	vulnArgs := []string{
		"--offering-slug", "cloud",
		"--limit", "25", "--cursor", "cur",
		"--severity", "high", "--status", "open", "--source", "scanner",
		"--updated-since", "2026-01-02T03:04:05Z",
	}
	knowledgeQuery := url.Values{
		"limit": {"5"}, "cursor": {"n"}, "q": {"access policy"},
		"category": {"Policies"}, "source": {"file"},
	}
	return []operationCall{
		{audience: "consumer", command: "export-audit-events", key: "reader", args: []string{"--org-slug", "acme", "--limit", "2", "--cursor", "next", "--q", "material one", "--outcome", "denied"}, method: "GET", path: "/api/v1/orgs/acme/audit-events", query: url.Values{"limit": {"2"}, "cursor": {"next"}, "q": {"material one"}, "outcome": {"denied"}}},
		{audience: "consumer", command: "get-site-organization", key: "", args: []string{}, method: "GET", path: "/api/v1/organization"},
		{audience: "consumer", command: "list-certification-materials", key: "", args: []string{"--org-slug", "acme", "--offering-slug", "cloud", "--limit", "2", "--cursor", "next"}, method: "GET", path: "/api/v1/orgs/acme/offerings/cloud/certification/materials", query: url.Values{"limit": {"2"}, "cursor": {"next"}}},
		{audience: "consumer", command: "get-certification-material", key: "", args: []string{"--org-slug", "acme", "--offering-slug", "cloud", "--material-id", "material-1"}, method: "GET", path: "/api/v1/orgs/acme/offerings/cloud/certification/materials/material-1"},
		{audience: "consumer", command: "download-certification-material", key: "", args: []string{"--org-slug", "acme", "--offering-slug", "cloud", "--material-id", "material-1"}, method: "GET", path: "/api/v1/orgs/acme/offerings/cloud/certification/materials/material-1/download"},
		{audience: "consumer", command: "list-certification-snapshots", key: "reader", args: []string{"--org-slug", "acme", "--offering-slug", "cloud", "--limit", "2", "--cursor", "next"}, method: "GET", path: "/api/v1/orgs/acme/offerings/cloud/certification/snapshots", query: url.Values{"limit": {"2"}, "cursor": {"next"}}},
		{audience: "consumer", command: "export-access-summaries", key: "reader", args: []string{"--org-slug", "acme", "--limit", "2", "--cursor", "next", "--q", "material one", "--outcome", "denied"}, method: "GET", path: "/api/v1/orgs/acme/access-summaries", query: url.Values{"limit": {"2"}, "cursor": {"next"}, "q": {"material one"}, "outcome": {"denied"}}},
		{audience: "admin", command: "list-certification-materials", key: "mgmt", args: []string{"--org-slug", "acme", "--offering-slug", "cloud", "--limit", "2", "--cursor", "next"}, method: "GET", path: "/api/admin/v1/orgs/acme/offerings/cloud/certification/materials", query: url.Values{"limit": {"2"}, "cursor": {"next"}}},
		{audience: "admin", command: "publish-certification-material", key: "mgmt", args: []string{"--org-slug", "acme", "--offering-slug", "cloud"}, method: "POST", path: "/api/admin/v1/orgs/acme/offerings/cloud/certification/materials", body: "{}"},
		{audience: "admin", command: "get-certification-material", key: "mgmt", args: []string{"--org-slug", "acme", "--offering-slug", "cloud", "--material-id", "material-1"}, method: "GET", path: "/api/admin/v1/orgs/acme/offerings/cloud/certification/materials/material-1"},
		{audience: "admin", command: "download-certification-material", key: "mgmt", args: []string{"--org-slug", "acme", "--offering-slug", "cloud", "--material-id", "material-1"}, method: "GET", path: "/api/admin/v1/orgs/acme/offerings/cloud/certification/materials/material-1/download"},
		{audience: "admin", command: "list-certification-snapshots", key: "mgmt", args: []string{"--org-slug", "acme", "--offering-slug", "cloud", "--limit", "2", "--cursor", "next"}, method: "GET", path: "/api/admin/v1/orgs/acme/offerings/cloud/certification/snapshots", query: url.Values{"limit": {"2"}, "cursor": {"next"}}},
		{audience: "admin", command: "publish-certification-snapshot", key: "mgmt", args: []string{"--org-slug", "acme", "--offering-slug", "cloud"}, method: "POST", path: "/api/admin/v1/orgs/acme/offerings/cloud/certification/snapshots", body: "{}"},
		{audience: "admin", command: "export-agency-inventory", key: "mgmt", args: []string{"--org-slug", "acme", "--limit", "2", "--cursor", "next"}, method: "GET", path: "/api/admin/v1/orgs/acme/agency-inventory", query: url.Values{"limit": {"2"}, "cursor": {"next"}}},
		{audience: "admin", command: "export-agency-history", key: "mgmt", args: []string{"--org-slug", "acme", "--limit", "2", "--cursor", "next"}, method: "GET", path: "/api/admin/v1/orgs/acme/agency-history", query: url.Values{"limit": {"2"}, "cursor": {"next"}}},
		{audience: "admin", command: "export-audit-events", key: "mgmt", args: []string{"--org-slug", "acme", "--limit", "2", "--cursor", "next", "--q", "material one", "--outcome", "denied"}, method: "GET", path: "/api/admin/v1/orgs/acme/audit-events", query: url.Values{"limit": {"2"}, "cursor": {"next"}, "q": {"material one"}, "outcome": {"denied"}}},
		{audience: "admin", command: "export-access-summaries", key: "mgmt", args: []string{"--org-slug", "acme", "--limit", "2", "--cursor", "next", "--q", "material one", "--outcome", "denied"}, method: "GET", path: "/api/admin/v1/orgs/acme/access-summaries", query: url.Values{"limit": {"2"}, "cursor": {"next"}, "q": {"material one"}, "outcome": {"denied"}}},
		{audience: "admin", command: "verify-agency-affiliation", key: "mgmt", args: []string{"--org-slug", "acme", "--company-id", "company-1"}, method: "PATCH", path: "/api/admin/v1/orgs/acme/agencies/company-1", body: "{}"},
		{audience: "admin", command: "create-agency-system", key: "mgmt", args: []string{"--org-slug", "acme"}, method: "POST", path: "/api/admin/v1/orgs/acme/agency-systems", body: "{}"},
		{audience: "admin", command: "update-agency-system", key: "mgmt", args: []string{"--org-slug", "acme", "--system-id", "system-1"}, method: "PATCH", path: "/api/admin/v1/orgs/acme/agency-systems/system-1", body: "{}"},
		{audience: "admin", command: "issue-agency-system-key", key: "mgmt", args: []string{"--org-slug", "acme", "--system-id", "system-1"}, method: "POST", path: "/api/admin/v1/orgs/acme/agency-systems/system-1/keys"},
		{audience: "consumer", command: "get-organization", args: []string{"--org-slug", "acme"}, method: "GET", path: "/api/v1/orgs/acme"},
		{audience: "consumer", command: "list-machine-readables", args: append([]string{"--org-slug", "acme"}, pageArgs...), method: "GET", path: "/api/v1/orgs/acme/machine-readables", query: page},
		{audience: "consumer", command: "get-machine-readable", args: []string{"--org-slug", "acme", "--document-slug", "pkg"}, method: "GET", path: "/api/v1/orgs/acme/machine-readables/pkg"},
		{audience: "consumer", command: "get-machine-readable-payload", args: []string{"--org-slug", "acme", "--document-slug", "pkg"}, method: "GET", path: "/api/v1/orgs/acme/machine-readables/pkg/payload"},
		{audience: "consumer", command: "list-incidents", args: append([]string{"--org-slug", "acme"}, pageArgs...), method: "GET", path: "/api/v1/orgs/acme/incidents", query: page},
		{audience: "consumer", command: "get-incident", args: []string{"--org-slug", "acme", "--incident-id", "11111111-1111-4111-8111-111111111111"}, method: "GET", path: "/api/v1/orgs/acme/incidents/11111111-1111-4111-8111-111111111111"},
		{audience: "consumer", command: "list-subprocessors", args: append([]string{"--org-slug", "acme"}, pageArgs...), method: "GET", path: "/api/v1/orgs/acme/subprocessors", query: page},
		{audience: "consumer", command: "get-subprocessor", args: []string{"--org-slug", "acme", "--subprocessor-slug", "aws"}, method: "GET", path: "/api/v1/orgs/acme/subprocessors/aws"},
		{audience: "consumer", command: "list-offerings", args: append([]string{"--org-slug", "acme"}, pageArgs...), method: "GET", path: "/api/v1/orgs/acme/offerings", query: page},
		{audience: "consumer", command: "get-offering", args: []string{"--org-slug", "acme", "--offering-slug", "cloud"}, method: "GET", path: "/api/v1/orgs/acme/offerings/cloud"},
		{audience: "consumer", command: "list-posture", args: append([]string{"--org-slug", "acme", "--offering-slug", "cloud"}, pageArgs...), method: "GET", path: "/api/v1/orgs/acme/offerings/cloud/posture", query: page},
		{audience: "consumer", command: "list-resources", args: append([]string{"--org-slug", "acme", "--offering-slug", "cloud"}, pageArgs...), method: "GET", path: "/api/v1/orgs/acme/offerings/cloud/resources", query: page},
		{audience: "consumer", command: "get-resource", args: []string{"--org-slug", "acme", "--offering-slug", "cloud", "--resource-slug", "overview"}, method: "GET", path: "/api/v1/orgs/acme/offerings/cloud/resources/overview"},
		{audience: "consumer", command: "list-vulnerabilities", key: "reader", args: append([]string{"--org-slug", "acme"}, vulnArgs...), method: "GET", path: "/api/v1/orgs/acme/offerings/cloud/vulnerabilities", query: vulnQuery},
		{audience: "consumer", command: "get-vulnerability", key: "reader", args: []string{"--org-slug", "acme", "--offering-slug", "cloud", "--finding-id", "finding-1"}, method: "GET", path: "/api/v1/orgs/acme/offerings/cloud/vulnerabilities/finding-1"},

		{audience: "admin", command: "get-organization", key: "mgmt", args: []string{"--org-slug", "acme"}, method: "GET", path: "/api/admin/v1/orgs/acme"},
		{audience: "admin", command: "update-organization", key: "mgmt", args: []string{"--org-slug", "acme"}, method: "PATCH", path: "/api/admin/v1/orgs/acme", body: `{"name":"Acme"}`},
		{audience: "admin", command: "list-machine-readables", key: "mgmt", args: append([]string{"--org-slug", "acme"}, pageArgs...), method: "GET", path: "/api/admin/v1/orgs/acme/machine-readables", query: page},
		{audience: "admin", command: "get-machine-readable", key: "mgmt", args: []string{"--org-slug", "acme", "--document-slug", "pkg"}, method: "GET", path: "/api/admin/v1/orgs/acme/machine-readables/pkg"},
		{audience: "admin", command: "upsert-machine-readable", key: "mgmt", args: []string{"--org-slug", "acme", "--document-slug", "pkg"}, method: "PUT", path: "/api/admin/v1/orgs/acme/machine-readables/pkg", body: `{"title":"Package","payload":{"offering":"Acme"}}`},
		{audience: "admin", command: "delete-machine-readable", key: "mgmt", args: []string{"--org-slug", "acme", "--document-slug", "pkg"}, method: "DELETE", path: "/api/admin/v1/orgs/acme/machine-readables/pkg"},
		{audience: "admin", command: "get-machine-readable-payload", key: "mgmt", args: []string{"--org-slug", "acme", "--document-slug", "pkg"}, method: "GET", path: "/api/admin/v1/orgs/acme/machine-readables/pkg/payload"},
		{audience: "admin", command: "replace-machine-readable-payload", key: "mgmt", args: []string{"--org-slug", "acme", "--document-slug", "pkg"}, method: "PUT", path: "/api/admin/v1/orgs/acme/machine-readables/pkg/payload", body: "{\"offering\":\"Acme\"}\n"},
		{audience: "admin", command: "list-knowledge", key: "mgmt", args: []string{"--org-slug", "acme", "--limit", "5", "--cursor", "n", "--q", "access policy", "--category", "Policies", "--source", "file"}, method: "GET", path: "/api/admin/v1/orgs/acme/knowledge", query: knowledgeQuery},
		{audience: "admin", command: "create-knowledge", key: "mgmt", args: []string{"--org-slug", "acme"}, method: "POST", path: "/api/admin/v1/orgs/acme/knowledge", body: `{"title":"Access policy","body":"Production access requires MFA."}`},
		{audience: "admin", command: "create-knowledge", key: "mgmt", args: []string{"--org-slug", "acme", "--title", "Policy", "--category", "Policies"}, method: "POST", path: "/api/admin/v1/orgs/acme/knowledge", fileName: "policy.txt", fileBody: "Rotate keys.", form: map[string]string{"title": "Policy", "category": "Policies"}},
		{audience: "admin", command: "get-knowledge", key: "mgmt", args: []string{"--org-slug", "acme", "--document-id", "doc-1"}, method: "GET", path: "/api/admin/v1/orgs/acme/knowledge/doc-1"},
		{audience: "admin", command: "replace-knowledge", key: "mgmt", args: []string{"--org-slug", "acme", "--document-id", "doc-1"}, method: "PUT", path: "/api/admin/v1/orgs/acme/knowledge/doc-1", body: `{"title":"Updated","body":"Quarterly reviews."}`},
		{audience: "admin", command: "delete-knowledge", key: "mgmt", args: []string{"--org-slug", "acme", "--document-id", "doc-1"}, method: "DELETE", path: "/api/admin/v1/orgs/acme/knowledge/doc-1"},
		{audience: "admin", command: "download-knowledge", key: "mgmt", args: []string{"--org-slug", "acme", "--document-id", "doc-1"}, method: "GET", path: "/api/admin/v1/orgs/acme/knowledge/doc-1/download"},
		{audience: "admin", command: "upload-logo", key: "mgmt", args: []string{"--org-slug", "acme"}, method: "POST", path: "/api/admin/v1/orgs/acme/assets", fileName: "logo.png", fileBody: "png-bytes"},
		{audience: "admin", command: "list-incidents", key: "mgmt", args: append([]string{"--org-slug", "acme"}, pageArgs...), method: "GET", path: "/api/admin/v1/orgs/acme/incidents", query: page},
		{audience: "admin", command: "create-incident", key: "mgmt", args: []string{"--org-slug", "acme"}, method: "POST", path: "/api/admin/v1/orgs/acme/incidents", body: `{"title":"Elevated error rate","body":"We are investigating elevated error rates.","status":"investigating"}`},
		{audience: "admin", command: "get-incident", key: "mgmt", args: []string{"--org-slug", "acme", "--incident-id", "11111111-1111-4111-8111-111111111111"}, method: "GET", path: "/api/admin/v1/orgs/acme/incidents/11111111-1111-4111-8111-111111111111"},
		{audience: "admin", command: "create-incident-update", key: "mgmt", args: []string{"--org-slug", "acme", "--incident-id", "11111111-1111-4111-8111-111111111111"}, method: "POST", path: "/api/admin/v1/orgs/acme/incidents/11111111-1111-4111-8111-111111111111/updates", body: `{"body":"A fix is rolling out.","status":"fixing"}`},
		{audience: "admin", command: "list-subprocessors", key: "mgmt", args: append([]string{"--org-slug", "acme"}, pageArgs...), method: "GET", path: "/api/admin/v1/orgs/acme/subprocessors", query: page},
		{audience: "admin", command: "get-subprocessor", key: "mgmt", args: []string{"--org-slug", "acme", "--subprocessor-slug", "aws"}, method: "GET", path: "/api/admin/v1/orgs/acme/subprocessors/aws"},
		{audience: "admin", command: "upsert-subprocessor", key: "mgmt", args: []string{"--org-slug", "acme", "--subprocessor-slug", "aws"}, method: "PUT", path: "/api/admin/v1/orgs/acme/subprocessors/aws", body: `{"name":"Amazon Web Services","purpose":"Hosting"}`},
		{audience: "admin", command: "delete-subprocessor", key: "mgmt", args: []string{"--org-slug", "acme", "--subprocessor-slug", "aws"}, method: "DELETE", path: "/api/admin/v1/orgs/acme/subprocessors/aws"},
		{audience: "admin", command: "list-offerings", key: "mgmt", args: append([]string{"--org-slug", "acme"}, pageArgs...), method: "GET", path: "/api/admin/v1/orgs/acme/offerings", query: page},
		{audience: "admin", command: "get-offering", key: "mgmt", args: []string{"--org-slug", "acme", "--offering-slug", "cloud"}, method: "GET", path: "/api/admin/v1/orgs/acme/offerings/cloud"},
		{audience: "admin", command: "upsert-offering", key: "mgmt", args: []string{"--org-slug", "acme", "--offering-slug", "cloud"}, method: "PUT", path: "/api/admin/v1/orgs/acme/offerings/cloud", body: `{"name":"Cloud"}`},
		{audience: "admin", command: "list-posture", key: "mgmt", args: append([]string{"--org-slug", "acme", "--offering-slug", "cloud"}, pageArgs...), method: "GET", path: "/api/admin/v1/orgs/acme/offerings/cloud/posture", query: page},
		{audience: "admin", command: "upsert-posture", key: "mgmt", args: []string{"--org-slug", "acme", "--offering-slug", "cloud"}, method: "PUT", path: "/api/admin/v1/orgs/acme/offerings/cloud/posture", body: `{"framework":"SOC 2","status":"certified"}`},
		{audience: "admin", command: "list-resources", key: "mgmt", args: append([]string{"--org-slug", "acme", "--offering-slug", "cloud"}, pageArgs...), method: "GET", path: "/api/admin/v1/orgs/acme/offerings/cloud/resources", query: page},
		{audience: "admin", command: "get-resource", key: "mgmt", args: []string{"--org-slug", "acme", "--offering-slug", "cloud", "--resource-slug", "overview"}, method: "GET", path: "/api/admin/v1/orgs/acme/offerings/cloud/resources/overview"},
		{audience: "admin", command: "upsert-resource", key: "mgmt", args: []string{"--org-slug", "acme", "--offering-slug", "cloud", "--resource-slug", "overview"}, method: "PUT", path: "/api/admin/v1/orgs/acme/offerings/cloud/resources/overview", body: `{"title":"Security overview","kind":"page"}`},
		{audience: "admin", command: "list-vulnerabilities", key: "mgmt", args: append([]string{"--org-slug", "acme"}, vulnArgs...), method: "GET", path: "/api/admin/v1/orgs/acme/offerings/cloud/vulnerabilities", query: vulnQuery},
		{audience: "admin", command: "upsert-vulnerabilities", key: "mgmt", args: []string{"--org-slug", "acme", "--offering-slug", "cloud"}, method: "PUT", path: "/api/admin/v1/orgs/acme/offerings/cloud/vulnerabilities", body: `{"vulnerabilities":[{"source":"scanner","externalId":"finding-1","title":"Example","severity":"high"}]}`},
		{audience: "admin", command: "get-vulnerability", key: "mgmt", args: []string{"--org-slug", "acme", "--offering-slug", "cloud", "--finding-id", "finding-1"}, method: "GET", path: "/api/admin/v1/orgs/acme/offerings/cloud/vulnerabilities/finding-1"},
	}
}

func TestEveryOperationSendsTheDocumentedRequest(t *testing.T) {
	const response = `{"ok":true}`
	for _, tc := range operationCalls() {
		t.Run(tc.audience+" "+tc.command+" "+tc.method, func(t *testing.T) {
			var got snap
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read body: %v", err)
				}
				query, err := url.ParseQuery(r.URL.RawQuery)
				if err != nil {
					t.Errorf("query: %v", err)
				}
				got = snap{
					method:      r.Method,
					requestURI:  r.RequestURI,
					contentType: r.Header.Get("Content-Type"),
					auth:        r.Header.Get("Authorization"),
					query:       query,
					body:        body,
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(response))
			}))
			defer srv.Close()

			args := []string{"--base-url", srv.URL, tc.audience, tc.command}
			args = append(args, tc.args...)
			if tc.key != "" {
				args = append(args, "--api-key", tc.key)
			}
			if tc.body != "" {
				args = append(args, "--body", tc.body)
			}
			if tc.fileName != "" {
				path := filepath.Join(t.TempDir(), tc.fileName)
				if err := os.WriteFile(path, []byte(tc.fileBody), 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--file", path)
			}
			code, stdout, stderr := run(t, args...)
			if code != 0 {
				t.Fatalf("exit %d\nstderr: %s", code, stderr)
			}
			if stdout != response {
				t.Fatalf("stdout %q", stdout)
			}
			if got.method != tc.method {
				t.Errorf("method %s, want %s", got.method, tc.method)
			}
			uri, err := url.ParseRequestURI(got.requestURI)
			if err != nil {
				t.Fatal(err)
			}
			if uri.EscapedPath() != tc.path {
				t.Errorf("path %s, want %s", uri.EscapedPath(), tc.path)
			}
			if !sameQuery(tc.query, got.query) {
				t.Errorf("query %v, want %v", got.query, tc.query)
			}
			wantAuth := ""
			if tc.key != "" {
				wantAuth = "Bearer " + tc.key
			}
			if got.auth != wantAuth {
				t.Errorf("authorization %q, want %q", got.auth, wantAuth)
			}
			switch {
			case tc.fileName != "":
				if !strings.HasPrefix(got.contentType, "multipart/form-data") {
					t.Fatalf("content type %q", got.contentType)
				}
				fields, filename, fileBody := parseMultipart(t, got.contentType, got.body)
				if filename != tc.fileName {
					t.Errorf("filename %s, want %s", filename, tc.fileName)
				}
				if string(fileBody) != tc.fileBody {
					t.Errorf("file body %q", fileBody)
				}
				if !reflect.DeepEqual(fields, tc.form) && !(len(fields) == 0 && len(tc.form) == 0) {
					t.Errorf("form %v, want %v", fields, tc.form)
				}
			case tc.body != "":
				if got.contentType != "application/json" {
					t.Errorf("content type %q", got.contentType)
				}
				if string(got.body) != tc.body {
					t.Errorf("body %q, want %q", got.body, tc.body)
				}
			default:
				if got.contentType != "" {
					t.Errorf("content type %q, want none", got.contentType)
				}
				if len(got.body) != 0 {
					t.Errorf("body %q, want empty", got.body)
				}
			}
		})
	}
}

type snap struct {
	method      string
	requestURI  string
	contentType string
	auth        string
	query       url.Values
	body        []byte
}

func sameQuery(want, got url.Values) bool {
	if len(want) == 0 && len(got) == 0 {
		return true
	}
	return reflect.DeepEqual(want, got)
}

func parseMultipart(t *testing.T, contentType string, body []byte) (map[string]string, string, []byte) {
	t.Helper()
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		t.Fatal(err)
	}
	if mediaType != "multipart/form-data" {
		t.Fatalf("media type %s", mediaType)
	}
	reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	fields := map[string]string{}
	var filename string
	var fileBody []byte
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		payload, err := io.ReadAll(part)
		if err != nil {
			t.Fatal(err)
		}
		if part.FileName() != "" {
			filename = part.FileName()
			fileBody = payload
			continue
		}
		fields[part.FormName()] = string(payload)
	}
	return fields, filename, fileBody
}

func TestHelpListsEveryOperation(t *testing.T) {
	for _, audience := range []string{"consumer", "admin"} {
		code, stdout, stderr := run(t, audience, "--help")
		if code != 0 {
			t.Fatalf("%s help exit %d: %s", audience, code, stderr)
		}
		if stderr != "" {
			t.Fatalf("stderr %q", stderr)
		}
		got := commandNames(stdout)
		want := map[string]bool{}
		for _, tc := range operationCalls() {
			if tc.audience == audience {
				want[tc.command] = true
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s commands\ngot %s\nwant %s", audience, strings.Join(sortedKeys(got), ","), strings.Join(sortedKeys(want), ","))
		}
	}
}

func commandNames(help string) map[string]bool {
	const header = "Available Commands:"
	_, after, ok := strings.Cut(help, header)
	if !ok {
		return nil
	}
	names := map[string]bool{}
	for line := range strings.SplitSeq(after, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			if len(names) > 0 {
				break
			}
			continue
		}
		if strings.HasPrefix(trimmed, "Flags:") || strings.HasPrefix(trimmed, "Usage:") || strings.HasPrefix(trimmed, "Global Flags:") {
			break
		}
		name := strings.Fields(trimmed)[0]
		if name == "help" || name == "completion" {
			continue
		}
		names[name] = true
	}
	return names
}

func sortedKeys(values map[string]bool) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func TestTheCommandIsNamedOt(t *testing.T) {
	code, stdout, stderr := run(t, "--help")
	if code != 0 {
		t.Fatal(stderr)
	}
	if !strings.Contains(stdout, "\n  ot [flags]\n") || strings.Contains(stdout, "opentrust") {
		t.Fatalf("help:\n%s", stdout)
	}
	code, stdout, stderr = run(t, "consumer", "get-organization", "--help")
	if code != 0 {
		t.Fatal(stderr)
	}
	if !strings.Contains(stdout, "ot consumer get-organization --org-slug <orgSlug>") {
		t.Fatalf("example:\n%s", stdout)
	}
	code, _, stderr = run(t, "--base-url", "ftp://files.example", "consumer", "get-organization", "--org-slug", "acme")
	if code != 2 || !strings.HasPrefix(stderr, "ot: ") {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
}

func TestOpentrustIsAnAliasForOt(t *testing.T) {
	original := os.Args[0]
	os.Args[0] = "opentrust"
	t.Cleanup(func() { os.Args[0] = original })

	code, stdout, stderr := run(t, "--help")
	if code != 0 {
		t.Fatal(stderr)
	}
	if !strings.Contains(stdout, "\n  opentrust [flags]\n") {
		t.Fatalf("help:\n%s", stdout)
	}
	code, _, stderr = run(t, "--base-url", "ftp://files.example", "consumer", "get-organization", "--org-slug", "acme")
	if code != 2 || !strings.HasPrefix(stderr, "opentrust: ") {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
}

func TestRootHelpNamesBothAPIs(t *testing.T) {
	code, stdout, stderr := run(t)
	if code != 0 {
		t.Fatalf("exit %d stderr %s", code, stderr)
	}
	if !strings.Contains(stdout, "consumer") || !strings.Contains(stdout, "admin") {
		t.Fatalf("help:\n%s", stdout)
	}
}

func TestCommandHelpDocumentsScopeAndPath(t *testing.T) {
	code, stdout, stderr := run(t, "consumer", "get-organization", "--help")
	if code != 0 {
		t.Fatalf("exit %d %s", code, stderr)
	}
	if !strings.Contains(stdout, "content:read") || !strings.Contains(stdout, "/api/v1/orgs/{orgSlug}") {
		t.Fatalf("help:\n%s", stdout)
	}
	code, stdout, stderr = run(t, "admin", "get-organization", "--help")
	if code != 0 {
		t.Fatalf("exit %d %s", code, stderr)
	}
	if !strings.Contains(stdout, "/api/admin/v1/orgs/{orgSlug}") || !strings.Contains(stdout, "Bearer API key required") {
		t.Fatalf("help:\n%s", stdout)
	}
	code, stdout, stderr = run(t, "management", "list-vulnerabilities", "--help")
	if code != 0 {
		t.Fatalf("alias exit %d %s", code, stderr)
	}
	if !strings.Contains(stdout, "vulnerabilities:read") || !strings.Contains(stdout, "/api/admin/v1/orgs/{orgSlug}/offerings/{offeringSlug}/vulnerabilities") {
		t.Fatalf("alias help:\n%s", stdout)
	}
}

func TestPublicReadCanSendAnAPIKey(t *testing.T) {
	got := serve(t, `{"data":{"slug":"northwind"}}`)
	code, stdout, stderr := run(t, "--base-url", got.url, "--api-key", "consumer-key", "consumer", "get-organization", "--org-slug", "northwind")
	if code != 0 {
		t.Fatal(stderr)
	}
	if stdout != `{"data":{"slug":"northwind"}}` {
		t.Fatalf("stdout %s", stdout)
	}
	if got.auth != "Bearer consumer-key" {
		t.Fatalf("auth %q", got.auth)
	}
	if got.path != "/api/v1/orgs/northwind" {
		t.Fatalf("path %s", got.path)
	}
}

func TestMissingCredentialsAndFlagsDoNotCallTheServer(t *testing.T) {
	cases := [][]string{
		{"consumer", "get-organization"},
		{"admin", "get-organization", "--org-slug", "acme"},
		{"consumer", "list-vulnerabilities", "--org-slug", "acme", "--offering-slug", "cloud"},
		{"admin", "upload-logo", "--org-slug", "acme", "--body", "{}"},
		{"admin", "create-knowledge", "--org-slug", "acme", "--api-key", "k", "--title", "Policy"},
		{"admin", "create-knowledge", "--org-slug", "acme", "--api-key", "k", "--file", "missing.txt", "--body", "{}"},
		{"--base-url", "ftp://files.example", "consumer", "get-organization", "--org-slug", "acme"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			got := serve(t, `{"ok":true}`)
			full := append([]string{"--base-url", got.url}, args...)
			if args[0] == "--base-url" {
				full = args
			}
			code, stdout, stderr := run(t, full...)
			if code != 2 {
				t.Fatalf("exit %d stdout %s stderr %s", code, stdout, stderr)
			}
			if stdout != "" {
				t.Fatalf("stdout %s", stdout)
			}
			if got.hits != 0 {
				t.Fatalf("server hits %d", got.hits)
			}
		})
	}
}

func TestFileUploadRequiresTitle(t *testing.T) {
	got := serve(t, `{"ok":true}`)
	path := filepath.Join(t.TempDir(), "policy.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := run(t, "--base-url", got.url, "--api-key", "k", "admin", "create-knowledge", "--org-slug", "acme", "--file", path)
	if code != 2 {
		t.Fatalf("exit %d %s", code, stderr)
	}
	if !strings.Contains(stderr, "--title") {
		t.Fatalf("stderr %s", stderr)
	}
	if got.hits != 0 {
		t.Fatalf("hits %d", got.hits)
	}
}

func TestBodyFileAndStdinAreSentUnchanged(t *testing.T) {
	payload := "{\n  \"offering\": \"CLI cloud\"\n}\n"
	got := serve(t, `{"ok":true}`)
	path := filepath.Join(t.TempDir(), "payload.json")
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--base-url", got.url, "--api-key", "k", "admin", "replace-machine-readable-payload", "--org-slug", "acme", "--document-slug", "pkg", "--body-file", path}
	code, _, stderr := run(t, args...)
	if code != 0 {
		t.Fatal(stderr)
	}
	if string(got.body) != payload {
		t.Fatalf("body %q", got.body)
	}

	got.hits = 0
	got.body = nil
	code, stdout, stderr := executeIn(payload, "--base-url", got.url, "--api-key", "k", "admin", "replace-machine-readable-payload", "--org-slug", "acme", "--document-slug", "pkg", "--body-file", "-")
	if code != 0 {
		t.Fatal(stderr)
	}
	if stdout != `{"ok":true}` || string(got.body) != payload {
		t.Fatalf("stdout %s body %q", stdout, got.body)
	}
}

func TestEnvironmentSuppliesBaseURLAndKey(t *testing.T) {
	got := serve(t, `{"ok":true}`)
	t.Setenv("OPENTRUST_BASE_URL", got.url)
	t.Setenv("OPENTRUST_API_KEY", "env-key")
	code, _, stderr := execute("admin", "get-organization", "--org-slug", "acme")
	if code != 0 {
		t.Fatal(stderr)
	}
	if got.path != "/api/admin/v1/orgs/acme" || got.auth != "Bearer env-key" {
		t.Fatalf("path %s auth %s", got.path, got.auth)
	}
}

func TestPathSegmentsAreEscaped(t *testing.T) {
	got := serve(t, `{"ok":true}`)
	code, _, stderr := run(t, "--base-url", got.url+"/", "consumer", "get-organization", "--org-slug", "a/b")
	if code != 0 {
		t.Fatal(stderr)
	}
	if !strings.HasPrefix(got.requestURI, "/api/v1/orgs/a%2Fb") {
		t.Fatalf("request URI %s", got.requestURI)
	}
}

func TestHTTPErrorIsReportedAndSuccessCanBeWrittenToAFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"code":"forbidden","message":"Wrong audience"}}`, http.StatusForbidden)
	}))
	defer srv.Close()
	out := filepath.Join(t.TempDir(), "body.json")
	code, stdout, stderr := run(t, "--base-url", srv.URL, "--out", out, "consumer", "get-organization", "--org-slug", "missing")
	if code != 1 || stdout != "" {
		t.Fatalf("exit %d stdout %q stderr %s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "returned 403") || !strings.Contains(stderr, `"code":"forbidden"`) && !strings.Contains(stderr, `"code": "forbidden"`) {
		t.Fatalf("stderr %s", stderr)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("wrote an output file for a failed request")
	}

	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		_, _ = w.Write([]byte("%PDF-1.4\n"))
	}))
	defer ok.Close()
	file := filepath.Join(t.TempDir(), "doc.pdf")
	code, stdout, stderr = run(t, "--base-url", ok.URL, "--api-key", "k", "--out", file, "admin", "download-knowledge", "--org-slug", "acme", "--document-id", "doc-1")
	if code != 0 {
		t.Fatal(stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout %q", stdout)
	}
	saved, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(saved) != "%PDF-1.4\n" {
		t.Fatalf("file %q", saved)
	}
}

func TestBinaryResponseIsNotRewritten(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("%PDF-1.4\n"))
	}))
	defer srv.Close()
	code, stdout, stderr := run(t, "--base-url", srv.URL, "--api-key", "k", "admin", "download-knowledge", "--org-slug", "acme", "--document-id", "doc-1")
	if code != 0 {
		t.Fatal(stderr)
	}
	if stdout != "%PDF-1.4\n" {
		t.Fatalf("stdout %q", stdout)
	}
}

type recorded struct {
	url        string
	hits       int
	auth       string
	path       string
	requestURI string
	body       []byte
}

func serve(t *testing.T, response string) *recorded {
	t.Helper()
	got := &recorded{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.hits++
		got.auth = r.Header.Get("Authorization")
		got.path = r.URL.EscapedPath()
		got.requestURI = r.RequestURI
		got.body = body
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
	got.url = srv.URL
	t.Cleanup(srv.Close)
	return got
}
