// Package cli is the OpenTrust command line.
// Execute is the process boundary: arguments and stdin in, stdout, stderr, and an exit code out.
package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"

	"github.com/EpykLab/ot/internal/openapi"
)

// Execute runs one CLI invocation.
// A nil stdin reads nothing. main passes os.Stdin.
func Execute(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if stdin == nil {
		stdin = bytes.NewReader(nil)
	}
	a := &app{
		name:   invokedName(),
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		client: &http.Client{Timeout: 60 * time.Second},
	}
	root, err := a.root()
	if err != nil {
		fmt.Fprintf(stderr, "%s: %s\n", a.name, err)
		return 1
	}
	root.SetArgs(args)
	err = root.Execute()
	if err == nil {
		return 0
	}
	var exit *exitError
	if errors.As(err, &exit) {
		if exit.msg != "" {
			fmt.Fprintln(stderr, exit.msg)
		}
		return exit.code
	}
	fmt.Fprintf(stderr, "%s: %s\n", a.name, err)
	return 2
}

func invokedName() string {
	name := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
	if name == "opentrust" {
		return "opentrust"
	}
	return "ot"
}

type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func (a *app) usagef(format string, args ...any) error {
	return &exitError{code: 2, msg: a.name + ": " + fmt.Sprintf(format, args...)}
}

func (a *app) failf(format string, args ...any) error {
	return &exitError{code: 1, msg: a.name + ": " + fmt.Sprintf(format, args...)}
}

type app struct {
	name   string
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	client *http.Client
}

func (a *app) root() (*cobra.Command, error) {
	root := a.command(a.name, "CLI for the OpenTrust consumer and management APIs")
	root.CompletionOptions.DisableDefaultCmd = true
	root.Long = fmt.Sprintf(`Call the OpenTrust consumer API (/api/v1) and management API (/api/admin/v1).

Response bodies are written to stdout unchanged so machine-readable JSON keeps its original bytes.

  %s consumer get-organization --org-slug northwind
  %s admin upsert-offering --org-slug northwind --offering-slug cloud --body '{"name":"Cloud"}'

Set OPENTRUST_BASE_URL and OPENTRUST_API_KEY, or pass --base-url and --api-key.
Settings may also live in $XDG_CONFIG_HOME/ot/config.toml, which is ~/.config/ot/config.toml when XDG_CONFIG_HOME is unset:

  base_url = "https://trust.example.com"
  api_key = "..."

Flags override those environment variables, which override the file.
The admin audience is also available as "management".`, a.name, a.name)
	root.RunE = func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	}
	cfg, err := loadUserConfig()
	if err != nil {
		return nil, err
	}
	root.PersistentFlags().String("base-url", firstNonEmpty(os.Getenv("OPENTRUST_BASE_URL"), cfg.BaseURL, "http://localhost:3000"), "OpenTrust base URL ($OPENTRUST_BASE_URL, or base_url in config.toml)")
	root.PersistentFlags().String("api-key", firstNonEmpty(os.Getenv("OPENTRUST_API_KEY"), cfg.APIKey), "Bearer API key ($OPENTRUST_API_KEY, or api_key in config.toml)")
	root.PersistentFlags().String("out", "", "Write the response body to this file instead of stdout")

	consumerOps, err := openapi.Load("consumer")
	if err != nil {
		return nil, err
	}
	adminOps, err := openapi.Load("admin")
	if err != nil {
		return nil, err
	}
	consumer, err := a.audience("consumer", "Call the OpenTrust consumer API (/api/v1).", nil, consumerOps)
	if err != nil {
		return nil, err
	}
	admin, err := a.audience("admin", "Call the OpenTrust management API (/api/admin/v1).", []string{"management"}, adminOps)
	if err != nil {
		return nil, err
	}
	root.AddCommand(consumer, admin)
	return root, nil
}

func (a *app) audience(name, short string, aliases []string, ops []openapi.Operation) (*cobra.Command, error) {
	cmd := a.command(name, short)
	cmd.Aliases = aliases
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	}
	for _, op := range ops {
		child, err := a.operation(name, op)
		if err != nil {
			return nil, err
		}
		cmd.AddCommand(child)
	}
	return cmd, nil
}

func (a *app) operation(audience string, op openapi.Operation) (*cobra.Command, error) {
	cmd := a.command(op.Command, op.Summary)
	cmd.Long = describe(op)
	cmd.Example = example(a.name, audience, op)
	cmd.Args = cobra.NoArgs
	for _, param := range op.Params {
		usage := param.Description
		if usage == "" {
			usage = param.Name
		}
		cmd.Flags().String(param.Flag, "", usage)
		if param.In == "path" {
			if err := cmd.MarkFlagRequired(param.Flag); err != nil {
				return nil, err
			}
		}
	}
	if op.JSON {
		cmd.Flags().String("body", "", "JSON request body")
		cmd.Flags().String("body-file", "", "File containing the request body, or - to read stdin")
	}
	if op.File {
		cmd.Flags().String("file", "", "File to send as the multipart file field")
		for _, field := range op.Form {
			usage := "Multipart form field " + field.Name
			if field.Required {
				usage += " (required with --file)"
			}
			cmd.Flags().String(field.Flag, "", usage)
		}
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return a.invoke(cmd, op)
	}
	return cmd, nil
}

func describe(op openapi.Operation) string {
	var b strings.Builder
	if op.Description != "" {
		b.WriteString(op.Description)
		b.WriteString("\n\n")
	}
	fmt.Fprintf(&b, "%s %s\nScope: %s\n", op.Method, op.Path, op.Scope)
	if op.Anonymous {
		b.WriteString("Authentication: optional Bearer API key\n")
	} else {
		b.WriteString("Authentication: Bearer API key required\n")
	}
	switch {
	case op.JSON && op.File:
		b.WriteString("Send JSON with --body or --body-file, or upload a file with --file.\n")
	case op.File:
		b.WriteString("Upload a file with --file.\n")
	case op.JSON:
		b.WriteString("Send the request body with --body or --body-file.\n")
	}
	return b.String()
}

func example(name, audience string, op openapi.Operation) string {
	parts := []string{name, audience, op.Command}
	for _, param := range op.Params {
		if param.In == "path" {
			parts = append(parts, "--"+param.Flag, "<"+param.Name+">")
		}
	}
	if op.JSON {
		parts = append(parts, "--body", "'<json>'")
	} else if op.File {
		parts = append(parts, "--file", "<path>")
	}
	return "  " + strings.Join(parts, " ")
}

func (a *app) command(use, short string) *cobra.Command {
	cmd := &cobra.Command{
		Use:           use,
		Short:         short,
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetOut(a.stdout)
	cmd.SetErr(a.stderr)
	return cmd
}

func (a *app) invoke(cmd *cobra.Command, op openapi.Operation) error {
	baseURL, err := cmd.Flags().GetString("base-url")
	if err != nil {
		return err
	}
	apiKey, err := cmd.Flags().GetString("api-key")
	if err != nil {
		return err
	}
	outPath, err := cmd.Flags().GetString("out")
	if err != nil {
		return err
	}
	apiKey = strings.TrimSpace(apiKey)
	if !op.Anonymous && apiKey == "" {
		return a.usagef("--api-key is required for %s", op.Command)
	}

	path := op.Path
	query := url.Values{}
	for _, param := range op.Params {
		value, err := cmd.Flags().GetString(param.Flag)
		if err != nil {
			return err
		}
		if param.In == "path" {
			if value == "" {
				return a.usagef("--%s is required", param.Flag)
			}
			path = strings.ReplaceAll(path, "{"+param.Name+"}", url.PathEscape(value))
			continue
		}
		if cmd.Flags().Changed(param.Flag) {
			query.Set(param.Name, value)
		}
	}

	payload, contentType, err := a.requestBody(cmd, op)
	if err != nil {
		return err
	}

	endpoint, err := a.endpointURL(baseURL, path, query)
	if err != nil {
		return err
	}
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(op.Method, endpoint, body)
	if err != nil {
		return a.failf("%s", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	req.Header.Set("User-Agent", "ot")

	resp, err := a.client.Do(req)
	if err != nil {
		return a.failf("%s %s: %s", op.Method, endpoint, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return a.failf("reading %s %s: %s", op.Method, endpoint, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := fmt.Sprintf("%s: %s %s returned %d", a.name, op.Method, endpoint, resp.StatusCode)
		if len(respBody) > 0 {
			msg += "\n" + string(respBody)
		}
		return &exitError{code: 1, msg: msg}
	}
	if outPath != "" {
		if err := os.WriteFile(outPath, respBody, 0o600); err != nil {
			return a.failf("writing %s: %s", outPath, err)
		}
		return nil
	}
	if _, err := a.stdout.Write(respBody); err != nil {
		return a.failf("writing response: %s", err)
	}
	return nil
}

func (a *app) requestBody(cmd *cobra.Command, op openapi.Operation) ([]byte, string, error) {
	var bodyText string
	var bodyFile string
	var filePath string
	if op.JSON {
		var err error
		bodyText, err = cmd.Flags().GetString("body")
		if err != nil {
			return nil, "", err
		}
		bodyFile, err = cmd.Flags().GetString("body-file")
		if err != nil {
			return nil, "", err
		}
	}
	if op.File {
		var err error
		filePath, err = cmd.Flags().GetString("file")
		if err != nil {
			return nil, "", err
		}
	}
	if cmdHas(cmd, "body") && cmdHas(cmd, "body-file") {
		return nil, "", a.usagef("pass either --body or --body-file, not both")
	}
	bodySet := cmdHas(cmd, "body") || cmdHas(cmd, "body-file")
	fileSet := cmdHas(cmd, "file")
	if bodySet && fileSet {
		return nil, "", a.usagef("pass either --body/--body-file or --file, not both")
	}
	if op.File && !fileSet {
		for _, field := range op.Form {
			if cmd.Flags().Changed(field.Flag) {
				return nil, "", a.usagef("--%s is only used with --file", field.Flag)
			}
		}
	}
	if fileSet {
		if strings.TrimSpace(filePath) == "" {
			return nil, "", a.usagef("--file requires a path")
		}
		return a.multipart(cmd, op, filePath)
	}
	if bodySet {
		if cmdHas(cmd, "body-file") {
			payload, err := a.readBodyFile(bodyFile)
			if err != nil {
				return nil, "", err
			}
			return payload, "application/json", nil
		}
		return []byte(bodyText), "application/json", nil
	}
	if op.BodyRequired {
		if op.File && !op.JSON {
			return nil, "", a.usagef("--file is required for %s", op.Command)
		}
		if op.JSON && op.File {
			return nil, "", a.usagef("--body, --body-file, or --file is required for %s", op.Command)
		}
		return nil, "", a.usagef("--body or --body-file is required for %s", op.Command)
	}
	return nil, "", nil
}

func cmdHas(cmd *cobra.Command, name string) bool {
	flag := cmd.Flags().Lookup(name)
	return flag != nil && flag.Changed
}

func (a *app) readBodyFile(path string) ([]byte, error) {
	if path == "-" {
		payload, err := io.ReadAll(a.stdin)
		if err != nil {
			return nil, a.failf("reading stdin: %s", err)
		}
		return payload, nil
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, a.failf("reading %s: %s", path, err)
	}
	return payload, nil
}

func (a *app) multipart(cmd *cobra.Command, op openapi.Operation, filePath string) ([]byte, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, "", a.failf("opening %s: %s", filePath, err)
	}
	defer file.Close()
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	for _, field := range op.Form {
		value, err := cmd.Flags().GetString(field.Flag)
		if err != nil {
			return nil, "", err
		}
		if field.Required && strings.TrimSpace(value) == "" {
			return nil, "", a.usagef("--%s is required to upload a file", field.Flag)
		}
		if !field.Required && !cmd.Flags().Changed(field.Flag) {
			continue
		}
		if err := writer.WriteField(field.Name, value); err != nil {
			return nil, "", a.failf("encoding form: %s", err)
		}
	}
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return nil, "", a.failf("encoding form: %s", err)
	}
	if _, err := io.Copy(part, file); err != nil {
		return nil, "", a.failf("reading %s: %s", filePath, err)
	}
	if err := writer.Close(); err != nil {
		return nil, "", a.failf("encoding form: %s", err)
	}
	return buf.Bytes(), writer.FormDataContentType(), nil
}

func (a *app) endpointURL(baseURL, path string, query url.Values) (string, error) {
	baseURL = strings.TrimSpace(baseURL)
	base, err := url.Parse(baseURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return "", a.usagef("--base-url must be an http or https URL")
	}
	ref, err := url.Parse(path)
	if err != nil {
		return "", a.usagef("invalid path %s", path)
	}
	if encoded := query.Encode(); encoded != "" {
		ref.RawQuery = encoded
	}
	return base.ResolveReference(ref).String(), nil
}

type fileConfig struct {
	BaseURL string `toml:"base_url"`
	APIKey  string `toml:"api_key"`
}

func loadUserConfig() (fileConfig, error) {
	path, err := configPath()
	if err != nil {
		return fileConfig{}, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileConfig{}, nil
	}
	if err != nil {
		return fileConfig{}, fmt.Errorf("%s: %w", path, err)
	}
	var cfg fileConfig
	decoder := toml.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		var strict *toml.StrictMissingError
		if errors.As(err, &strict) {
			names := make([]string, 0, len(strict.Errors))
			for _, item := range strict.Errors {
				names = append(names, strings.Join(item.Key(), "."))
			}
			return fileConfig{}, fmt.Errorf("%s: unknown setting %s", path, strings.Join(names, ", "))
		}
		return fileConfig{}, fmt.Errorf("%s: %w", path, err)
	}
	cfg.BaseURL = strings.TrimSpace(cfg.BaseURL)
	cfg.APIKey = strings.TrimSpace(cfg.APIKey)
	return cfg, nil
}

func configPath() (string, error) {
	dir := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME"))
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("finding the home directory: %w", err)
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "ot", "config.toml"), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
