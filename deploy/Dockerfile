# A LofSwap seed node in a container.
#
#   docker build -f deploy/Dockerfile -t lofswap-node .
#   docker run -d --name lofswap-node -p 6000:6000 -v lofswap-data:/data lofswap-node
#
# Build it from the repository root — the node needs blockchain-core too.

FROM rust:1-slim-bookworm AS build
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY blockchain-core ./blockchain-core
COPY node-cli ./node-cli
COPY wallet-cli ./wallet-cli
COPY wallet-gui ./wallet-gui
COPY explorer-api ./explorer-api
COPY lofswap-logo.png ./lofswap-logo.png
RUN cargo build --release -p node-cli

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /data lofswap
COPY --from=build /src/target/release/node-cli /usr/local/bin/node-cli

# The chain, the mempool and the peer list all live here; mount a volume on it.
ENV DATA_DIR=/data
VOLUME ["/data"]
WORKDIR /data
USER lofswap
EXPOSE 6000

# UPnP is pointless in a datacentre: the port is published by the host, and the
# probe only adds startup delay.
ENTRYPOINT ["node-cli", "--no-upnp"]
