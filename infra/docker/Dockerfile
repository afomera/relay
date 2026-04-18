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

RUN cargo build --release --bin relayd

# ---- runtime stage ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --home /var/lib/relay --create-home relay
WORKDIR /var/lib/relay

COPY --from=build /src/target/release/relayd /usr/local/bin/relayd

USER relay
EXPOSE 80 443 443/udp

ENTRYPOINT ["/usr/local/bin/relayd"]
CMD ["--config", "/etc/relay/relayd.toml"]
