# pops-gateway — multi-stage image.
#
# Stage 1 builds the `pops-gateway` binary from the workspace; stage 2 is a slim
# runtime that carries only the binary. The operator mounts ONE config at
# /etc/pops-gateway/config.toml and points clients at the gateway.
#
# Build context = the WORKSPACE ROOT (the gateway depends on the sibling
# path-crates pops-core-verify / pops-core-types, and on cdk as a git dep, so
# the whole workspace + .cargo/config.toml must be in context):
#
#   docker build -f crates/pops-gateway/Dockerfile -t pops-gateway .
#
# (The published image — ghcr.io/makeprisms/pops-gateway — is produced by
# CI/release; this Dockerfile is the buildable shape, no local build for the
# operator.)

# ── Stage 1: builder ────────────────────────────────────────────────────────
FROM rust:1.95-slim-bookworm AS builder

# git: the cdk dependency is a git source (MakePrisms/cdk, fetched over HTTPS via
# the git CLI — see .cargo/config.toml `git-fetch-with-cli = true`).
# pkg-config + libssl-dev: native TLS / secp build inputs. ca-certificates: the
# HTTPS git fetch + crates.io.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the whole workspace (path deps + the .cargo config that selects the git
# CLI fetcher). A release build of just the gateway binary.
COPY . .

RUN cargo build --release --locked -p pops-gateway

# ── Stage 2: runtime ────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# ca-certificates so the gateway's outbound TLS (mint swap + readiness probe +
# upstream forward) validates. No toolchain in the runtime image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user. The operator mounts a writable volume for proofs_sink.
RUN useradd --system --uid 10001 --home /var/lib/pops-gateway --create-home pops \
    && mkdir -p /etc/pops-gateway \
    && chown -R pops:pops /var/lib/pops-gateway

COPY --from=builder /build/target/release/pops-gateway /usr/local/bin/pops-gateway

USER pops

# The gateway reads its single declarative config from here (mount it):
#   -v ./config.toml:/etc/pops-gateway/config.toml
# Override the path with POPS_GATEWAY_CONFIG if you mount elsewhere.
ENV POPS_GATEWAY_CONFIG=/etc/pops-gateway/config.toml

# Default listen port (config `listen` may override; keep them in sync).
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/pops-gateway"]
