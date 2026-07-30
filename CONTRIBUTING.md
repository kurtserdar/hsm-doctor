# Contributing to HSM Doctor

Thanks for your interest in improving HSM Doctor. This guide covers building,
testing and the conventions the project follows.

## Development setup

Requirements:

- Go 1.24+ and a C compiler (cgo — the PKCS#11 wrapper and trace shim use it)
- [SoftHSM2](https://github.com/softhsm/SoftHSMv2) and OpenSC for the
  integration and Flight Recorder tests
- Node.js 20+ to rebuild the web UI (`make ui`)
- Docker or a PostgreSQL server for the Postgres store tests (optional)

```sh
git clone https://github.com/kurtserdar/hsm-doctor.git
cd hsm-doctor
make build          # CLI only
make ui build       # CLI with the embedded web interface
make shim           # the PKCS#11 Flight Recorder shim (hsmdoctor-trace.so)
```

## Testing

HSM Doctor has layered tests; please run the ones relevant to your change.

```sh
make test                       # unit tests — pure logic, no HSM
make integration                # SoftHSM-backed integration tests (tag: integration)
```

- **Unit tests** must pass with no HSM present. Keep pure logic (policy
  engine, analyzers, parsers, notifiers) unit-testable with fakes.
- **Integration tests** are guarded by the `integration` build tag and use a
  throwaway SoftHSM token created in a temp directory — they need no root and
  never touch your real token store. Point them at a specific module with
  `HSMDOCTOR_TEST_MODULE=/path/to/libsofthsm2.so` if needed.
- **PostgreSQL** store conformance runs when `HSMDOCTOR_TEST_POSTGRES` is set
  to a DSN, e.g.
  `HSMDOCTOR_TEST_POSTGRES=postgres://postgres:secret@127.0.0.1:5432/hsmdoctor?sslmode=disable`.
  The SQLite backend runs the same conformance suite on every test run.
- **Flight Recorder** end-to-end: `make shim`, then drive `pkcs11-tool
  --module ./hsmdoctor-trace.so ...` against SoftHSM (see
  [docs/trace.md](docs/trace.md)). CI does this and asserts no PIN appears in
  the trace.

Before opening a pull request, please make sure these pass:

```sh
gofmt -l .            # must print nothing
go vet ./...
go vet -tags=integration ./...
golangci-lint run ./...
golangci-lint run --build-tags integration ./...
go test ./...
```

CI additionally runs the integration, Postgres and shim suites, a Kryoptic
post-quantum check, and `govulncheck`.

## Conventions

- **Code comments and identifiers are in English.**
- **Commit messages are in English** and describe the change and its
  rationale. Keep the subject line focused; use the body for the "why".
- Match the surrounding code's style, naming and comment density. A comment
  should state a constraint the code cannot, not narrate what the next line
  does.
- Add or update tests with every change when feasible. If a change genuinely
  can't be tested without real vendor hardware, say so in the PR.
- Keep secrets out of logs and traces. PINs, key material, plaintext, DSN
  passwords and SMTP passwords must never be logged. The trace shim is
  secret-safe by construction — keep it that way.

## Adding a vendor provider

Vendor providers live in `internal/vendors/<name>` and implement the
`Provider` interface, registering themselves in `init()`. Depend on
`vendor.Runner` for any external command so the provider is testable with
canned fixtures. See `internal/vendors/softhsm` for a complete, stable
example and [docs/vendors.md](docs/vendors.md) for the authoring guide.
Corrections to the experimental Luna/nShield/CloudHSM providers from real
hardware are especially welcome.

## Reporting security issues

Please do **not** open a public issue for security vulnerabilities. See
[SECURITY.md](SECURITY.md) for private reporting.
