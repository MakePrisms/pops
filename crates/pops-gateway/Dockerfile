# pops-gateway — multi-stage image.
#
# Stage 1 builds the `pops-gateway` binary from the workspace; stage 2 is a slim
# runtime that carries only the binary. The operator mounts ONE config at
# /etc/pops-gateway/config.toml and points clients at the gateway.
#
# Build context = the WORKSPACE ROOT (the gateway depends on the sibling
# path-crates pops-core-verify / pops-core-types, so the whole workspace must
# be in context):
#
#   docker build -f crates/pops-gateway/Dockerfile -t pops-gateway .
#
# (The published image — ghcr.io/makeprisms/pops-gateway — is produced by
# CI/release; this Dockerfile is the buildable shape, no local build for the
# operator.)

# ── Stage 1: builder ────────────────────────────────────────────────────────
FROM rust:1.95-slim-bookworm AS builder

# pkg-config + libssl-dev: native TLS / secp build inputs. ca-certificates: the
# crates.io fetch.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the whole workspace (path deps). A release build of just the gateway
# binary.
COPY . .

RUN cargo build --release --locked -p pops-gateway

# ── Stage 2: runtime ────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# ca-certificates so the gateway's outbound TLS (mint swap + readiness probe +
# upstream forward) validates. No toolchain in the runtime image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (uid 10001). The operator mounts a writable volume for
# proofs_sink.
#
# IMPORTANT — proofs_sink must be writable BY THIS uid (10001), not just by the
# host user. The gateway runs a REAL write-probe at startup (create+fsync+delete
# a temp file in the proofs_sink dir as uid 10001) and FAILS FAST if it cannot
# write — so a volume owned by host root (or any other uid) is caught at boot
# instead of silently EACCES-ing on the first redeemed proof (= lost value).
#
# Make the mounted volume writable to uid 10001 with EITHER:
#   (a) chown the host dir to the container uid before running:
#         mkdir -p ./data && sudo chown 10001:10001 ./data
#         docker run -v ./data:/data ...                 # proofs_sink=/data/...
#   (b) OR run the container as your own uid AND chown to it:
#         docker run --user "$(id -u):$(id -g)" -v ./data:/data ...
#       (./data must then be owned by that uid; /etc/pops-gateway must be
#        readable by it — the mounted config typically already is.)
# A named docker volume (docker volume create) inherits the image's ownership of
# its mountpoint, so the default `pops` uid can write it without a host chown.
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
