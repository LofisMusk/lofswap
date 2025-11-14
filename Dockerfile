# ---- BUILD STAGE ----
FROM rust:latest AS builder

WORKDIR /build

# pliki workspaca
COPY Cargo.toml Cargo.lock ./

# podciągamy pod-crates potrzebne do zbudowania node-cli
COPY blockchain-core ./blockchain-core
COPY wallet-cli ./wallet-cli
COPY node-cli ./node-cli
COPY gui-app ./gui-app

# build tylko dla node-cli (pakiet/binary o nazwie "node-cli")
RUN cargo build -r -p node-cli
ENTRYPOINT [ "/build/target/release/node-cli" ]
# ---- RUNTIME STAGE ----
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# kopiujemy binarkę
COPY --from=builder /build/target/release/node-cli ./node-cli

RUN mkdir -p /app/data

ENTRYPOINT ["./node-cli"]
