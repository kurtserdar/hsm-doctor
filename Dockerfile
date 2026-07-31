# syntax=docker/dockerfile:1

# ---- build stage -------------------------------------------------------------
# cgo needs a C compiler; the web UI is pre-built and committed under
# internal/server/ui/dist, so no Node.js is required to build the image.
FROM golang:1.25-bookworm AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=docker
RUN CGO_ENABLED=1 go build -trimpath \
      -ldflags "-X github.com/kurtserdar/hsm-doctor/internal/version.Version=${VERSION} \
                -X github.com/kurtserdar/hsm-doctor/internal/version.Commit=${COMMIT}" \
      -o /out/hsmdoctor ./cmd/hsmdoctor

# ---- runtime stage -----------------------------------------------------------
# Ships SoftHSM2 and OpenSC so the image is usable out of the box for trying
# the CLI and web UI; point --module at a real vendor library for production.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends softhsm2 opensc ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user with a writable SoftHSM token store.
RUN useradd --create-home --uid 10001 hsm \
    && mkdir -p /home/hsm/tokens \
    && printf 'directories.tokendir = /home/hsm/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' \
       > /home/hsm/softhsm2.conf \
    && chown -R hsm:hsm /home/hsm

COPY --from=build /out/hsmdoctor /usr/local/bin/hsmdoctor

USER hsm
ENV SOFTHSM2_CONF=/home/hsm/softhsm2.conf
# The web server binds loopback by default; pass --listen 0.0.0.0:8080 to expose it.
EXPOSE 8080
ENTRYPOINT ["hsmdoctor"]
CMD ["--help"]
