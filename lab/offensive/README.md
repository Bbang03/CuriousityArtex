# Offensive tool runner

This service assesses registered API schemas, URL/HAR request inventories and source ZIPs, and retains two local practice profiles. It does not modify the
Defensive, Splunk, or Closed-loop implementation.

| Profile | Target | Tool | Result meaning |
| --- | --- | --- | --- |
| `api` / `crapi` | Local OWASP crAPI | Schemathesis 4.30.1 | Response-check candidates, not confirmed security findings |
| `source` / `benchmark` | OWASP Benchmark Java source | Semgrep CE 1.180.0 | Static review candidates, not dynamically reproduced vulnerabilities |

The API profile registers a disposable ordinary account in the local crAPI
instance and tries to authenticate. Credentials are held only in memory; the
result explicitly records whether authentication succeeded. It selects six
fixed read-oriented GET routes from the mounted official OpenAPI document.
It uses a single fuzzing phase with a five-example limit per operation, three
requests per second, and a 125-second outer process deadline. There is no
time-based repeated fuzzing mode. It limits redirects and artifact size too.
It does not cover cross-account authorization or the complete crAPI surface.

The source profile scans only Java test code using the five reviewed local
rules in `rules/java-security.yml`. The rules identify potentially dangerous
API usage; ARTEX must review input flows and defenses before reporting a
confirmed issue. Expected-results files and answer labels are not mounted.
Source hashes, repository revision, tool version, rules, and analysis output
are retained. No Benchmark web server is required for this static profile.

## Uploaded targets

`POST /targets` accepts a bounded JSON envelope with `kind`, `name`, `filename`,
`content_base64`, and `base_url` for APIs. The authenticated web backend accepts
multipart uploads and converts them to this internal envelope. Schema files
are limited to 8 MiB; source ZIPs to 20 MiB with bounded extraction. ZIP paths,
symlinks, duplicates, and decompression limits are checked before publication.
Targets receive immutable UUIDs and a SHA-256 provenance value.

Uploaded APIs expose GET/HEAD operations from an OpenAPI JSON/YAML document.
The run selects at most 40 operation IDs (`GET /path`) and may supply a transient
`bearer_token`. The runner does not create accounts on user targets. Alternate
schema servers and external references cannot redirect the scan scope. The
scoped schema used for execution is published with the result. Source scans
support Java, Python, JavaScript and TypeScript using bundled local rules; they
do not build or execute uploaded projects.

## API discovery without a supplied schema

`input_mode` defaults to `openapi`. API registration also supports:

- `url`: `kind`, `name`, `base_url`, `input_mode` only; no file. Read-only,
  bounded static HTML/linked-JavaScript discovery on the same origin and path
  prefix, without executing scripts or automating login.
- `har`: `filename`, `content_base64` (HAR JSON, <=16 MiB), and optional
  `har_origin` in addition to those fields. Only matching-origin GET/HEAD
  requests inside the chosen path prefix are retained. Explicit `har_origin`
  maps a browser origin such as localhost to the operator's runtime origin;
  it is never contacted by the runner.

The target stores `input_mode`, `scope_url`, provenance hashes, safe operation
metadata and `discovery` summary/warnings. HAR raw headers, cookies, query
values and request/response bodies are not stored or replayed. Per-run bearer
authentication remains separate. Static JS paths are inferred candidates;
a recorded HAR request does not prove successful authorization or security.

A generated minimal OpenAPI document drives bounded GET/HEAD request generation.
It is an execution inventory, not an API response contract. URL/HAR assessments
therefore use `not_a_server_error` only, not schema/status contract conformance.
Discovery warnings and original operation scope are preserved in the evidence
and passed to ARTEX review. Zero candidates is not a security clearance.

## Interface

The service listens on port `8090`. Every route except `GET /health` requires
the bearer token from `ARTEX_OFFENSIVE_TOKEN_FILE` (at least 24 characters).
The token must not be exposed in browser JavaScript; the ARTEX backend proxies
these routes after its own user authentication.

- `GET /catalog`: example and uploaded targets, operations, languages, tool versions, readiness.
- `POST /targets`: register an OpenAPI document, URL discovery, HAR or source ZIP; returns the target.
- `GET /runs`: latest 100 runs.
- `POST /runs`: `kind` and `target_id` (example ID or uploaded UUID), plus optional
  API `operation_ids` and transient `bearer_token`. One active scan at a time.
- `GET /runs/{uuid}`: progress, candidates, limitations, artifacts.
- `GET /runs/{uuid}/artifacts/{name}`: a manifest-listed artifact after hash
  verification.
- `POST /runs/{uuid}/task`: `{"task_id":"123"}` binds a completed run to one
  ARTEX task. Repeating the same ID is idempotent; a different ID conflicts.

Run state is persisted in `/data/offensive/runs`. ARTEX sees the same directory
at `/app/data/offensive/runs`. Each finished run provides `report.json` as its
stable review input. Example source references use `/app/offensive/benchmark`.
Uploaded source references use `/app/data/offensive/targets/{uuid}/source`,
mounted read-only in ARTEX. Run snapshots preserve the selected target and scope.
After service restart, unfinished runs become `interrupted`; they are never
silently labeled completed.

## Configuration

| Variable | Default |
| --- | --- |
| `ARTEX_OFFENSIVE_TOKEN_FILE` | Required secret file |
| `OFFENSIVE_PORT` | `8090` |
| `OFFENSIVE_DATA_DIR` | `/data/offensive/runs` |
| `OFFENSIVE_TARGETS_DIR` | Sibling `targets` directory of the run directory |
| `OFFENSIVE_CRAPI_URL` | `http://crapi-web:80` |
| `OFFENSIVE_SCHEMA_PATH` | `/opt/crapi-schema` |
| `OFFENSIVE_BENCHMARK_PATH` | `/opt/benchmark` |
| `OFFENSIVE_RULES_PATH` | `/app/rules/java-security.yml` |
| `OFFENSIVE_CRAPI_REVISION` | Set by the local lab deployment |
| `OFFENSIVE_BENCHMARK_REVISION` | Set by the local lab deployment |

Mount source, schema, rules, and token read-only. The runner needs no Docker
socket. Vulnerable lab services use an internal Compose network. Only the runner
adds an egress network for registered API destinations. ARTEX provides the runner UI;
a separate reverse proxy publishes crAPI and its practice mailbox on localhost.
Do not expose the runner port publicly.

## Tests

```sh
python3 -m unittest discover -s lab/offensive -p 'test_*.py'
```

The tests cover target selection, schema scope, credential redaction,
safe ZIP/schema/HAR ingestion, URL discovery boundaries, credential minimization, user operation scope, restart recovery, deadline
enforcement, artifact integrity, HTTP authentication, and concurrent task association.
