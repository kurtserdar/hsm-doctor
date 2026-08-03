BINARY  := hsmdoctor
MODULE  := github.com/kurtserdar/hsm-doctor
VERSION ?= 1.14.0
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -X $(MODULE)/internal/version.Version=$(VERSION) \
           -X $(MODULE)/internal/version.Commit=$(COMMIT)

SHIM := hsmdoctor-trace.so

.PHONY: build shim ui test integration vet fmt clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/hsmdoctor

# Builds the PKCS#11 Flight Recorder shim as a c-shared library (needs cgo).
shim:
	CGO_ENABLED=1 go build -buildmode=c-shared -o $(SHIM) ./shim

# Builds the web interface into internal/server/ui/dist (requires Node.js).
# Run "make ui build" to produce a binary with the embedded UI.
ui:
	cd web && npm install && npm run build

test:
	go test ./...

# Integration tests require SoftHSM2; see docs/testing.md
integration:
	go test -tags=integration ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

clean:
	rm -f $(BINARY) $(SHIM) hsmdoctor-trace.h coverage.out
