# OpenTrust CLI

`ot` calls OpenTrust's Consumer and Management APIs. `opentrust` is an alias binary; `management` is an alias for the `admin` command group.

Install from this checkout:

```sh
go install ./cmd/ot ./cmd/opentrust
```

Configure `OPENTRUST_BASE_URL`, `OPENTRUST_ORG_SLUG`, and `OPENTRUST_API_KEY`, or use `~/.config/ot/config.toml`. Use an existing Management key with `content:read` for organization-wide audit exports. Consumer keys can retrieve only their authorized agency/account events and summaries. Keep credentials out of command arguments and exported files.

## Retrieve audit evidence

```sh
ot admin export-audit-events --all --out audit-events.json
ot admin export-audit-events --outcome denied --q certification --all --out denied-requests.json
ot admin export-access-summaries --all --out access-summaries.json
ot admin export-agency-history --all --out agency-history.json
ot admin export-agency-inventory --all --out agency-inventory.json
ot consumer export-audit-events --all --out my-audit-events.json
ot consumer export-access-summaries --all --out my-access-summaries.json
```

Consumer event and summary queries derive the agency boundary from the authenticated identity, or fall back to that principal alone when no agency affiliation is recorded. Request-supplied identities and cursors cannot broaden this boundary. The signed-in portal links to **My access logs** at `/account/access`.

Individual audit events are newest first by timestamp and ID. They include principal/agency, target/version, action, outcome, HTTP status, request ID, and observation time. `prepared` means the server prepared a response; it does not establish receipt or reading. Missing records do not prove uninterrupted coverage.

Use `--limit` and `--cursor` to retrieve an individual page. Without `--all`, the response bytes are written unchanged. `--all` follows opaque cursors, preserves filters and first-page metadata, combines `data` arrays into one JSON response, and sets `nextCursor` to null. An initial `--cursor` starts from that page. The combined export is held in memory. Malformed pagination, repeated cursors, or failed requests cause a nonzero exit and leave the output file untouched. Results reflect observed records rather than a database snapshot; later requests can create additional evidence.

The same pagination option works for other cursor-paginated list commands. Published certification documents, including original files, are available through `list-certification-materials`, `get-certification-material`, `download-certification-material`, and `list-certification-snapshots` in the appropriate audience. Run a command with `--help` for its required slugs and IDs.

## API contracts and checks

Commands are generated from the bundled Consumer and Management OpenAPI documents in `internal/openapi`. Update both together from a reviewed OpenTrust server's `/openapi.json` and `/api/admin/openapi.json`, then run:

```sh
go test ./... -skip TestLiveOpenTrust
go vet ./...
go build ./cmd/ot ./cmd/opentrust
```

`TestLiveOpenTrust` is a separate test requiring a running seeded local OpenTrust server and local fixture database. For isolated audit export integration, build `ot` to a temporary path and run `OPENTRUST_CLI_PATH=/path/to/ot pnpm test:status` from the OpenTrust server checkout after `pnpm build`.
