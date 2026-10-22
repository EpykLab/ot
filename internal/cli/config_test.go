package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigFileSuppliesBaseURLAndAPIKey(t *testing.T) {
	got := serve(t, `{"ok":true}`)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("OPENTRUST_BASE_URL", "")
	t.Setenv("OPENTRUST_API_KEY", "")
	writeConfig(t, "base_url = \""+got.url+"\"\napi_key = \"file-key\"\n")

	code, stdout, stderr := execute("admin", "get-organization", "--org-slug", "acme")
	if code != 0 {
		t.Fatal(stderr)
	}
	if stdout != `{"ok":true}` {
		t.Fatalf("stdout %s", stdout)
	}
	if got.path != "/api/admin/v1/orgs/acme" || got.auth != "Bearer file-key" {
		t.Fatalf("path %s auth %s", got.path, got.auth)
	}
}

func TestConfigFileIsSharedByTheOpentrustAlias(t *testing.T) {
	original := os.Args[0]
	os.Args[0] = "opentrust"
	t.Cleanup(func() { os.Args[0] = original })

	got := serve(t, `{"ok":true}`)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("OPENTRUST_BASE_URL", "")
	t.Setenv("OPENTRUST_API_KEY", "")
	writeConfig(t, "base_url = \""+got.url+"\"\napi_key = \"alias-key\"\n")

	code, _, stderr := execute("admin", "get-organization", "--org-slug", "acme")
	if code != 0 {
		t.Fatal(stderr)
	}
	if got.auth != "Bearer alias-key" {
		t.Fatalf("auth %s", got.auth)
	}
}

func TestEnvironmentAndFlagsOverrideConfigFile(t *testing.T) {
	fileServer := serve(t, `{"ok":true}`)
	envServer := serve(t, `{"ok":true}`)
	flagServer := serve(t, `{"ok":true}`)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	writeConfig(t, "base_url = \""+fileServer.url+"\"\napi_key = \"file-key\"\n")

	t.Setenv("OPENTRUST_BASE_URL", envServer.url)
	t.Setenv("OPENTRUST_API_KEY", "env-key")
	code, _, stderr := execute("admin", "get-organization", "--org-slug", "acme")
	if code != 0 {
		t.Fatal(stderr)
	}
	if envServer.hits != 1 || envServer.auth != "Bearer env-key" || fileServer.hits != 0 {
		t.Fatalf("env override file hits=%d env hits=%d auth=%s", fileServer.hits, envServer.hits, envServer.auth)
	}

	code, _, stderr = execute("--base-url", flagServer.url, "--api-key", "flag-key", "admin", "get-organization", "--org-slug", "acme")
	if code != 0 {
		t.Fatal(stderr)
	}
	if flagServer.hits != 1 || flagServer.auth != "Bearer flag-key" || envServer.hits != 1 {
		t.Fatalf("flag override env hits=%d flag hits=%d auth=%s", envServer.hits, flagServer.hits, flagServer.auth)
	}
}

func TestPartialConfigStillAllowsTheOtherSource(t *testing.T) {
	got := serve(t, `{"ok":true}`)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("OPENTRUST_BASE_URL", "")
	t.Setenv("OPENTRUST_API_KEY", "")
	writeConfig(t, "base_url = \""+got.url+"\"\n")

	code, _, stderr := execute("consumer", "get-organization", "--org-slug", "acme")
	if code != 0 {
		t.Fatal(stderr)
	}
	if got.hits != 1 || got.auth != "" || got.path != "/api/v1/orgs/acme" {
		t.Fatalf("hits %d auth %q path %s", got.hits, got.auth, got.path)
	}
}

func TestMissingConfigFileIsIgnored(t *testing.T) {
	got := serve(t, `{"ok":true}`)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("OPENTRUST_BASE_URL", "")
	t.Setenv("OPENTRUST_API_KEY", "")

	code, _, stderr := execute("--base-url", got.url, "consumer", "get-organization", "--org-slug", "acme")
	if code != 0 {
		t.Fatal(stderr)
	}
	if got.hits != 1 {
		t.Fatalf("hits %d", got.hits)
	}
}

func TestHomeConfigDirIsUsedWhenXDGConfigHomeIsUnset(t *testing.T) {
	got := serve(t, `{"ok":true}`)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("OPENTRUST_BASE_URL", "")
	t.Setenv("OPENTRUST_API_KEY", "")
	path := filepath.Join(home, ".config", "ot", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("base_url = \""+got.url+"\"\napi_key = \"home-key\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := execute("admin", "get-organization", "--org-slug", "acme")
	if code != 0 {
		t.Fatal(stderr)
	}
	if got.auth != "Bearer home-key" || got.path != "/api/admin/v1/orgs/acme" {
		t.Fatalf("path %s auth %s", got.path, got.auth)
	}
}

func TestInvalidConfigFileIsReported(t *testing.T) {
	got := serve(t, `{"ok":true}`)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("OPENTRUST_BASE_URL", "")
	t.Setenv("OPENTRUST_API_KEY", "")
	writeConfig(t, "base_url = [\n")

	code, stdout, stderr := execute("--base-url", got.url, "consumer", "get-organization", "--org-slug", "acme")
	if code != 1 || stdout != "" || got.hits != 0 {
		t.Fatalf("exit %d hits %d stdout %q stderr %s", code, got.hits, stdout, stderr)
	}
	if !strings.Contains(stderr, "config.toml") {
		t.Fatalf("stderr %s", stderr)
	}

	writeConfig(t, "baseURL = \"http://example.test\"\n")
	code, stdout, stderr = execute("--base-url", got.url, "consumer", "get-organization", "--org-slug", "acme")
	if code != 1 || stdout != "" || got.hits != 0 || !strings.Contains(stderr, "baseURL") {
		t.Fatalf("exit %d hits %d stdout %q stderr %s", code, got.hits, stdout, stderr)
	}
}

func TestHelpMentionsConfigFile(t *testing.T) {
	code, stdout, stderr := run(t, "--help")
	if code != 0 {
		t.Fatal(stderr)
	}
	if !strings.Contains(stdout, "$XDG_CONFIG_HOME/ot/config.toml") || !strings.Contains(stdout, "base_url") || !strings.Contains(stdout, "api_key") || !strings.Contains(stdout, "org_slug") || !strings.Contains(stdout, "offering_slug") {
		t.Fatalf("help:\n%s", stdout)
	}
}

func TestConfigFileSuppliesOrgSlug(t *testing.T) {
	got := serve(t, `{"ok":true}`)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("OPENTRUST_BASE_URL", "")
	t.Setenv("OPENTRUST_API_KEY", "")
	t.Setenv("OPENTRUST_ORG_SLUG", "")
	writeConfig(t, "base_url = \""+got.url+"\"\napi_key = \"file-key\"\norg_slug = \"northwind\"\n")

	code, stdout, stderr := execute("admin", "get-organization")
	if code != 0 {
		t.Fatal(stderr)
	}
	if stdout != `{"ok":true}` {
		t.Fatalf("stdout %s", stdout)
	}
	if got.path != "/api/admin/v1/orgs/northwind" || got.auth != "Bearer file-key" {
		t.Fatalf("path %s auth %s", got.path, got.auth)
	}

	code, _, stderr = execute("consumer", "get-offering", "--offering-slug", "cloud")
	if code != 0 {
		t.Fatal(stderr)
	}
	if got.path != "/api/v1/orgs/northwind/offerings/cloud" {
		t.Fatalf("path %s", got.path)
	}
}

func TestEnvironmentAndFlagsOverrideConfigOrgSlug(t *testing.T) {
	got := serve(t, `{"ok":true}`)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("OPENTRUST_BASE_URL", "")
	t.Setenv("OPENTRUST_API_KEY", "env-key")
	writeConfig(t, "base_url = \""+got.url+"\"\norg_slug = \"from-file\"\n")

	t.Setenv("OPENTRUST_ORG_SLUG", "from-env")
	code, _, stderr := execute("admin", "get-organization")
	if code != 0 {
		t.Fatal(stderr)
	}
	if got.path != "/api/admin/v1/orgs/from-env" {
		t.Fatalf("env path %s", got.path)
	}

	code, _, stderr = execute("admin", "get-organization", "--org-slug", "from-flag")
	if code != 0 {
		t.Fatal(stderr)
	}
	if got.path != "/api/admin/v1/orgs/from-flag" {
		t.Fatalf("flag path %s", got.path)
	}
}

func TestConfigFileSuppliesOfferingSlug(t *testing.T) {
	got := serve(t, `{"ok":true}`)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("OPENTRUST_BASE_URL", "")
	t.Setenv("OPENTRUST_API_KEY", "")
	t.Setenv("OPENTRUST_ORG_SLUG", "")
	t.Setenv("OPENTRUST_OFFERING_SLUG", "")
	writeConfig(t, "base_url = \""+got.url+"\"\napi_key = \"file-key\"\norg_slug = \"northwind\"\noffering_slug = \"cloud\"\n")

	code, stdout, stderr := execute("admin", "list-vulnerabilities")
	if code != 0 {
		t.Fatal(stderr)
	}
	if stdout != `{"ok":true}` {
		t.Fatalf("stdout %s", stdout)
	}
	if got.path != "/api/admin/v1/orgs/northwind/offerings/cloud/vulnerabilities" || got.auth != "Bearer file-key" {
		t.Fatalf("path %s auth %s", got.path, got.auth)
	}

	code, _, stderr = execute("consumer", "get-organization")
	if code != 0 {
		t.Fatal(stderr)
	}
	if got.path != "/api/v1/orgs/northwind" {
		t.Fatalf("path %s", got.path)
	}
}

func TestEnvironmentAndFlagsOverrideConfigOfferingSlug(t *testing.T) {
	got := serve(t, `{"ok":true}`)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("OPENTRUST_BASE_URL", "")
	t.Setenv("OPENTRUST_API_KEY", "env-key")
	t.Setenv("OPENTRUST_ORG_SLUG", "acme")
	writeConfig(t, "base_url = \""+got.url+"\"\noffering_slug = \"from-file\"\n")

	t.Setenv("OPENTRUST_OFFERING_SLUG", "from-env")
	code, _, stderr := execute("admin", "list-vulnerabilities")
	if code != 0 {
		t.Fatal(stderr)
	}
	if got.path != "/api/admin/v1/orgs/acme/offerings/from-env/vulnerabilities" {
		t.Fatalf("env path %s", got.path)
	}

	code, _, stderr = execute("admin", "list-vulnerabilities", "--offering-slug", "from-flag")
	if code != 0 {
		t.Fatal(stderr)
	}
	if got.path != "/api/admin/v1/orgs/acme/offerings/from-flag/vulnerabilities" {
		t.Fatalf("flag path %s", got.path)
	}
}

func TestBlankConfigOfferingSlugStaysRequired(t *testing.T) {
	got := serve(t, `{"ok":true}`)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("OPENTRUST_BASE_URL", "")
	t.Setenv("OPENTRUST_API_KEY", "")
	t.Setenv("OPENTRUST_ORG_SLUG", "acme")
	t.Setenv("OPENTRUST_OFFERING_SLUG", "   ")
	writeConfig(t, "base_url = \""+got.url+"\"\noffering_slug = \"  \"\n")

	code, stdout, stderr := execute("admin", "list-vulnerabilities")
	if code != 2 || stdout != "" || got.hits != 0 || !strings.Contains(stderr, "offering-slug") {
		t.Fatalf("exit %d hits %d stdout %q stderr %s", code, got.hits, stdout, stderr)
	}
}

func TestBlankConfigOrgSlugStaysRequired(t *testing.T) {
	got := serve(t, `{"ok":true}`)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("OPENTRUST_BASE_URL", "")
	t.Setenv("OPENTRUST_API_KEY", "")
	t.Setenv("OPENTRUST_ORG_SLUG", "   ")
	writeConfig(t, "base_url = \""+got.url+"\"\norg_slug = \"  \"\n")

	code, stdout, stderr := execute("consumer", "get-organization")
	if code != 2 || stdout != "" || got.hits != 0 || !strings.Contains(stderr, "org-slug") {
		t.Fatalf("exit %d hits %d stdout %q stderr %s", code, got.hits, stdout, stderr)
	}
}

func writeConfig(t *testing.T, body string) {
	t.Helper()
	dir := os.Getenv("XDG_CONFIG_HOME")
	path := filepath.Join(dir, "ot", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
