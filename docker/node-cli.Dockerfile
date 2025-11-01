## Multi-stage build for node-cli

# 1) Build stage: compile the Rust binary
FROM rust:1.81-bullseye AS builder
WORKDIR /app

# Copy the entire workspace (simple approach; relies on Docker layer cache between builds)
COPY Cargo.toml Cargo.lock ./
COPY blockchain-core ./blockchain-core
COPY wallet-cli ./wallet-cli
COPY node-cli ./node-cli

# Build only the node-cli binary in release mode
RUN cargo build --release -p node-cli


# 2) Runtime stage: minimal image with the compiled binary
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary
COPY --from=builder /app/target/release/node-cli /usr/local/bin/node-cli

# Create a working directory for data files written/read by the app
WORKDIR /data

# Expose P2P port and the explorer HTTP port
EXPOSE 6000 7000

# Defaults; can be overridden at runtime
ENV RUST_BACKTRACE=1 \
    BIND_ADDR=0.0.0.0 \
    EXPLORER_BIND_ADDR=0.0.0.0

# Run the node. Add flags here if you want different defaults, e.g. "--no-upnp".
ENTRYPOINT ["node-cli"]

