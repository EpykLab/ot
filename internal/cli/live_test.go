package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestLiveOpenTrust(t *testing.T) {
	base := "http://localhost:3000"
	if value := os.Getenv("OPENTRUST_BASE_URL"); value != "" {
		base = value
	}
	t.Setenv("OPENTRUST_API_KEY", "")
	health, err := http.Get(base + "/api/health")
	if err != nil {
		t.Fatalf("OpenTrust is not running at %s: %v", base, err)
	}
	health.Body.Close()
	if health.StatusCode != http.StatusOK {
		t.Fatalf("OpenTrust health returned %d", health.StatusCode)
	}

	t.Run("seeded northwind portal", func(t *testing.T) {
		body := liveOK(t, base, "", "consumer", "get-organization", "--org-slug", "northwind")
		org := dataObject(t, body)
		if org["name"] != "Northwind Security" || org["slug"] != "northwind" {
			t.Fatalf("organization %#v", org)
		}
		listed := dataList(t, liveOK(t, base, "", "consumer", "list-offerings", "--org-slug", "northwind"))
		if !listHas(listed, "slug", "cloud") {
			t.Fatalf("offerings %#v", listed)
		}
	})

	env := newLiveOrg(t, base)
	t.Run("management key can read the consumer profile", func(t *testing.T) {
		org := dataObject(t, liveOK(t, base, env.management, "consumer", "get-organization", "--org-slug", env.slug))
		if org["name"] != env.name || org["slug"] != env.slug {
			t.Fatalf("organization %#v", org)
		}
	})
	t.Run("consumer key is rejected by the management API", func(t *testing.T) {
		code, _, stderr := liveRun(t, base, env.consumer, "admin", "get-organization", "--org-slug", env.slug)
		if code != 1 || !strings.Contains(stderr, "returned 403") || !strings.Contains(stderr, "wrong_key_audience") {
			t.Fatalf("exit %d\n%s", code, stderr)
		}
	})
	t.Run("public resource is readable without a key", func(t *testing.T) {
		liveOK(t, base, env.management, "admin", "upsert-offering", "--org-slug", env.slug, "--offering-slug", "platform", "--body", `{"name":"Platform","description":"CLI test offering"}`)
		liveOK(t, base, env.management, "admin", "upsert-resource", "--org-slug", env.slug, "--offering-slug", "platform", "--resource-slug", "overview", "--body", `{"title":"Security overview","kind":"page","visibility":"public","body":"We encrypt customer data."}`)
		resource := dataObject(t, liveOK(t, base, "", "consumer", "get-resource", "--org-slug", env.slug, "--offering-slug", "platform", "--resource-slug", "overview"))
		if resource["title"] != "Security overview" || resource["body"] != "We encrypt customer data." {
			t.Fatalf("resource %#v", resource)
		}
	})
	t.Run("unpublished subprocessor requires a consumer key", func(t *testing.T) {
		liveOK(t, base, env.management, "admin", "upsert-subprocessor", "--org-slug", env.slug, "--subprocessor-slug", "cli-mail", "--body", `{"name":"CLI Mail","purpose":"Send notices","isPublic":false}`)
		code, _, stderr := liveRun(t, base, "", "consumer", "get-subprocessor", "--org-slug", env.slug, "--subprocessor-slug", "cli-mail")
		if code != 1 || !strings.Contains(stderr, "returned 401") || !strings.Contains(stderr, "has not been published") {
			t.Fatalf("anonymous exit %d\n%s", code, stderr)
		}
		row := dataObject(t, liveOK(t, base, env.consumer, "consumer", "get-subprocessor", "--org-slug", env.slug, "--subprocessor-slug", "cli-mail"))
		if row["name"] != "CLI Mail" || row["isPublic"] != false {
			t.Fatalf("subprocessor %#v", row)
		}
		liveOK(t, base, env.management, "admin", "delete-subprocessor", "--org-slug", env.slug, "--subprocessor-slug", "cli-mail")
		code, _, stderr = liveRun(t, base, env.consumer, "consumer", "get-subprocessor", "--org-slug", env.slug, "--subprocessor-slug", "cli-mail")
		if code != 1 || !strings.Contains(stderr, "returned 404") {
			t.Fatalf("deleted exit %d\n%s", code, stderr)
		}
	})
	t.Run("machine-readable payload bytes are preserved", func(t *testing.T) {
		liveOK(t, base, env.management, "admin", "upsert-machine-readable", "--org-slug", env.slug, "--document-slug", "package-overview", "--body", `{"title":"Package overview","visibility":"public","payload":{"offering":"placeholder"}}`)
		payload := []byte("{\n  \"offering\": \"CLI cloud\"\n}\n")
		file := filepath.Join(t.TempDir(), "package-overview.json")
		if err := os.WriteFile(file, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		liveOK(t, base, env.management, "admin", "replace-machine-readable-payload", "--org-slug", env.slug, "--document-slug", "package-overview", "--body-file", file)
		got := liveOK(t, base, "", "consumer", "get-machine-readable-payload", "--org-slug", env.slug, "--document-slug", "package-overview")
		if !bytes.Equal(got, payload) {
			t.Fatalf("payload\n%s\nwant\n%s", got, payload)
		}
		liveOK(t, base, env.management, "admin", "delete-machine-readable", "--org-slug", env.slug, "--document-slug", "package-overview")
		code, _, stderr := liveRun(t, base, "", "consumer", "get-machine-readable-payload", "--org-slug", env.slug, "--document-slug", "package-overview")
		if code != 1 || !strings.Contains(stderr, "returned 404") {
			t.Fatalf("deleted payload exit %d\n%s", code, stderr)
		}
	})
	t.Run("incident updates stay on one public timeline", func(t *testing.T) {
		created := dataObject(t, liveOK(t, base, env.management, "admin", "create-incident", "--org-slug", env.slug, "--body", `{"title":"Sign-in delays","body":"Customers are seeing slow sign-in.","status":"open","externalId":"cli-incident-1"}`))
		id, _ := created["id"].(string)
		updates, _ := created["updates"].([]any)
		if id == "" || created["status"] != "open" || len(updates) != 1 {
			t.Fatalf("created %#v", created)
		}
		replay := dataObject(t, liveOK(t, base, env.management, "admin", "create-incident", "--org-slug", env.slug, "--body", `{"title":"Sign-in delays","body":"Customers are seeing slow sign-in.","status":"closed","externalId":"cli-incident-1"}`))
		replayUpdates, _ := replay["updates"].([]any)
		if replay["id"] != id || replay["status"] != "open" || len(replayUpdates) != 1 {
			t.Fatalf("replay %#v", replay)
		}
		updated := dataObject(t, liveOK(t, base, env.management, "admin", "create-incident-update", "--org-slug", env.slug, "--incident-id", id, "--body", `{"status":"investigating"}`))
		updatedItems, _ := updated["updates"].([]any)
		if updated["status"] != "investigating" || len(updatedItems) != 2 {
			t.Fatalf("updated %#v", updated)
		}
		code, _, stderr := liveRun(t, base, env.consumer, "admin", "create-incident-update", "--org-slug", env.slug, "--incident-id", id, "--body", `{"status":"closed"}`)
		if code != 1 || !strings.Contains(stderr, "returned 403") {
			t.Fatalf("consumer write exit %d\n%s", code, stderr)
		}
		public := dataObject(t, liveOK(t, base, "", "consumer", "get-incident", "--org-slug", env.slug, "--incident-id", id))
		publicItems, _ := public["updates"].([]any)
		encoded, err := json.Marshal(public)
		if err != nil {
			t.Fatal(err)
		}
		if public["title"] != "Sign-in delays" || len(publicItems) != 2 || strings.Contains(string(encoded), "cli-incident-1") || strings.Contains(string(encoded), "externalId") {
			t.Fatalf("public %#v", public)
		}
	})
	t.Run("vulnerability push is readable with a consumer key", func(t *testing.T) {
		liveOK(t, base, env.management, "admin", "upsert-offering", "--org-slug", env.slug, "--offering-slug", "platform", "--body", `{"name":"Platform","description":"CLI test offering"}`)
		created := dataList(t, liveOK(t, base, env.management, "admin", "upsert-vulnerabilities", "--org-slug", env.slug, "--offering-slug", "platform", "--body", `{"vulnerabilities":[{"source":"scanner","externalId":"finding-001","title":"Example finding","severity":"high","status":"open","componentName":"example-package","componentVersion":"1.0.0"}]}`))
		if len(created) != 1 || created[0]["title"] != "Example finding" {
			t.Fatalf("created %#v", created)
		}
		id, _ := created[0]["id"].(string)
		if id == "" {
			t.Fatal("finding id missing")
		}
		code, _, stderr := liveRun(t, base, "", "consumer", "list-vulnerabilities", "--org-slug", env.slug, "--offering-slug", "platform")
		if code != 2 || !strings.Contains(stderr, "--api-key is required") {
			t.Fatalf("anonymous exit %d\n%s", code, stderr)
		}
		listed := dataList(t, liveOK(t, base, env.consumer, "consumer", "list-vulnerabilities", "--org-slug", env.slug, "--offering-slug", "platform", "--source", "scanner", "--severity", "high"))
		if len(listed) != 1 || listed[0]["externalId"] != "finding-001" {
			t.Fatalf("list %#v", listed)
		}
		one := dataObject(t, liveOK(t, base, env.consumer, "consumer", "get-vulnerability", "--org-slug", env.slug, "--offering-slug", "platform", "--finding-id", id))
		if one["title"] != "Example finding" || one["status"] != "open" {
			t.Fatalf("finding %#v", one)
		}
	})
	t.Run("knowledge article can be replaced and removed", func(t *testing.T) {
		created := dataObject(t, liveOK(t, base, env.management, "admin", "create-knowledge", "--org-slug", env.slug, "--body", `{"title":"Access policy","category":"Policies","body":"Production access requires MFA."}`))
		id, _ := created["id"].(string)
		if id == "" || created["body"] != "Production access requires MFA." {
			t.Fatalf("created %#v", created)
		}
		replaced := dataObject(t, liveOK(t, base, env.management, "admin", "replace-knowledge", "--org-slug", env.slug, "--document-id", id, "--body", `{"title":"Access policy","category":"Policies","body":"Production access requires MFA and quarterly reviews."}`))
		if replaced["body"] != "Production access requires MFA and quarterly reviews." {
			t.Fatalf("replaced %#v", replaced)
		}
		liveOK(t, base, env.management, "admin", "delete-knowledge", "--org-slug", env.slug, "--document-id", id)
		code, _, stderr := liveRun(t, base, env.management, "admin", "get-knowledge", "--org-slug", env.slug, "--document-id", id)
		if code != 1 || !strings.Contains(stderr, "returned 404") {
			t.Fatalf("deleted exit %d\n%s", code, stderr)
		}
	})
	t.Run("knowledge file round trip", func(t *testing.T) {
		original := []byte("Rotate keys quarterly.\n")
		file := filepath.Join(t.TempDir(), "notes.txt")
		if err := os.WriteFile(file, original, 0o600); err != nil {
			t.Fatal(err)
		}
		created := dataObject(t, liveOK(t, base, env.management, "admin", "create-knowledge", "--org-slug", env.slug, "--title", "Notes", "--category", "Policies", "--file", file))
		id, _ := created["id"].(string)
		if id == "" || created["body"] != "Rotate keys quarterly." || created["originalFilename"] != "notes.txt" {
			t.Fatalf("created %#v", created)
		}
		downloaded := liveOK(t, base, env.management, "admin", "download-knowledge", "--org-slug", env.slug, "--document-id", id)
		if !bytes.Equal(downloaded, original) {
			t.Fatalf("download %q", downloaded)
		}
		liveOK(t, base, env.management, "admin", "delete-knowledge", "--org-slug", env.slug, "--document-id", id)
	})
	t.Run("logo upload", func(t *testing.T) {
		var buf bytes.Buffer
		img := image.NewNRGBA(image.Rect(0, 0, 8, 8))
		img.Set(0, 0, color.NRGBA{R: 200, G: 16, B: 16, A: 255})
		if err := png.Encode(&buf, img); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(t.TempDir(), "logo.png")
		if err := os.WriteFile(file, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		asset := dataObject(t, liveOK(t, base, env.management, "admin", "upload-logo", "--org-slug", env.slug, "--file", file))
		id, _ := asset["id"].(string)
		url, _ := asset["url"].(string)
		if id == "" || asset["contentType"] != "image/webp" || !strings.HasPrefix(url, "/api/assets/") {
			t.Fatalf("asset %#v", asset)
		}
	})
}

type liveOrg struct {
	slug       string
	name       string
	management string
	consumer   string
}

func newLiveOrg(t *testing.T, base string) liveOrg {
	t.Helper()
	dsn := os.Getenv("OPENTRUST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://opentrust:opentrust@localhost:5432/opentrust?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to OpenTrust database: %v", err)
	}
	suffix := randomHex(t, 4)
	env := liveOrg{
		slug:       "cli" + suffix,
		name:       "CLI Test " + suffix,
		management: "ot_mgmt_" + suffix,
		consumer:   "ot_read_" + suffix,
	}
	orgID := "org_" + suffix
	userID := "user_" + suffix
	companyID := "co_" + suffix
	enrollmentID := "en_" + suffix
	domain := env.slug + ".example"
	email := "reader@" + domain
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		rows, err := conn.Query(cleanupCtx, `
			SELECT storage_key FROM asset WHERE organization_id = $1
			UNION ALL
			SELECT storage_key FROM knowledge_document WHERE organization_id = $1 AND storage_key IS NOT NULL`, orgID)
		if err == nil {
			for rows.Next() {
				var key string
				if rows.Scan(&key) == nil {
					removeStoredObject(key)
				}
			}
			rows.Close()
		}
		_, _ = conn.Exec(cleanupCtx, `DELETE FROM organization WHERE id = $1`, orgID)
		_, _ = conn.Exec(cleanupCtx, `DELETE FROM "user" WHERE id = $1`, userID)
		conn.Close(cleanupCtx)
	})
	mustExec(t, ctx, conn, `INSERT INTO "user" (id, name, email, email_verified, disabled, created_at, updated_at) VALUES ($1, $2, $3, true, false, now(), now())`, userID, "CLI Reader", email)
	mustExec(t, ctx, conn, `INSERT INTO organization (id, name, slug, created_at, metadata) VALUES ($1, $2, $3, now(), $4)`, orgID, env.name, env.slug, `{"vulnerabilityAccess":"approved"}`)
	mustExec(t, ctx, conn, `INSERT INTO consumer_organization (id, host_organization_id, name, domain) VALUES ($1, $2, $3, $4)`, companyID, orgID, "CLI Customer", domain)
	mustExec(t, ctx, conn, `INSERT INTO consumer_enrollment (id, consumer_organization_id, user_id, verified_email, status) VALUES ($1, $2, $3, $4, 'approved')`, enrollmentID, companyID, userID, email)
	mustExec(t, ctx, conn, `INSERT INTO api_key (id, organization_id, name, prefix, hashed_key, audience, scopes, expires_at) VALUES ($1, $2, $3, $4, $5, 'management', $6, now() + interval '1 day')`,
		"key_mgmt_"+suffix, orgID, "management", env.management[:10], hashKey(env.management), "content:read,content:write,knowledge:read,knowledge:write,vulnerabilities:read,vulnerabilities:write")
	mustExec(t, ctx, conn, `INSERT INTO api_key (id, organization_id, name, prefix, hashed_key, audience, scopes, consumer_enrollment_id, expires_at) VALUES ($1, $2, $3, $4, $5, 'consumer', $6, $7, now() + interval '1 day')`,
		"key_read_"+suffix, orgID, "consumer", env.consumer[:10], hashKey(env.consumer), "content:read,vulnerabilities:read", enrollmentID)
	return env
}

func mustExec(t *testing.T, ctx context.Context, conn *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := conn.Exec(ctx, sql, args...); err != nil {
		t.Fatal(err)
	}
}

func hashKey(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buf)
}

func removeStoredObject(storageKey string) {
	key := strings.TrimPrefix(storageKey, "local://")
	if strings.Contains(key, "://") {
		return
	}
	root := objectRoot()
	full := filepath.Join(root, filepath.FromSlash(key))
	if !strings.HasPrefix(full, root+string(os.PathSeparator)) {
		return
	}
	_ = os.Remove(full)
}

func objectRoot() string {
	if dir := strings.TrimSpace(os.Getenv("OPENTRUST_OBJECT_DIR")); dir != "" {
		return filepath.Clean(dir)
	}
	// go test runs in the package directory. OpenTrust is a sibling of this module.
	return filepath.Clean(filepath.Join("..", "..", "..", "OpenTrust", "data", "objects"))
}

func liveRun(t *testing.T, base, key string, args ...string) (int, []byte, string) {
	t.Helper()
	full := []string{"--base-url", base}
	if key != "" {
		full = append(full, "--api-key", key)
	}
	full = append(full, args...)
	var stdout, stderr bytes.Buffer
	code := Execute(full, bytes.NewReader(nil), &stdout, &stderr)
	return code, stdout.Bytes(), stderr.String()
}

func liveOK(t *testing.T, base, key string, args ...string) []byte {
	t.Helper()
	code, stdout, stderr := liveRun(t, base, key, args...)
	if code != 0 {
		t.Fatalf("opentrust %s\nexit %d\n%s", strings.Join(args, " "), code, stderr)
	}
	return stdout
}

func dataObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var env struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("json: %v\n%s", err, raw)
	}
	return env.Data
}

func dataList(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var env struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("json: %v\n%s", err, raw)
	}
	return env.Data
}

func listHas(rows []map[string]any, key, value string) bool {
	for _, row := range rows {
		if row[key] == value {
			return true
		}
	}
	return false
}
