# syntax=docker/dockerfile:1.6

# ---- build stage ----
FROM rust:1.85-slim-bookworm AS build
WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace manifest + source.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY migrations ./migrations

# Cache mounts persist cargo registry + target/ + rustup toolchain across
# builds. Without them, every `docker compose up --build` (a) recompiles
# the whole dep graph, and (b) re-downloads ~150MB of rust-std/rustc/etc.
# because rust-toolchain.toml pins `stable`, which drifts past whatever
# the base image preinstalled. The final `cp` is required because cache
# content is discarded after the RUN, so we copy the binary out first.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/rustup \
    --mount=type=cache,target=/src/target \
    cargo build --release --bin relayd && \
    cp /src/target/release/relayd /relayd

# ---- runtime stage ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --home /var/lib/relay --create-home relay
WORKDIR /var/lib/relay

COPY --from=build /relayd /usr/local/bin/relayd

USER relay
EXPOSE 80 443 443/udp

ENTRYPOINT ["/usr/local/bin/relayd"]
CMD ["--config", "/etc/relay/relayd.toml"]
