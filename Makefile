BINARY  := hsmdoctor
MODULE  := github.com/kurtserdar/hsm-doctor
VERSION ?= 0.1.0-dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -X $(MODULE)/internal/version.Version=$(VERSION) \
           -X $(MODULE)/internal/version.Commit=$(COMMIT)

.PHONY: build test integration vet fmt clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/hsmdoctor

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
	rm -f $(BINARY) coverage.out
