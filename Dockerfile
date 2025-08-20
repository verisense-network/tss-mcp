# syntax=docker/dockerfile:1

FROM rust:bookworm AS builder
WORKDIR /app

# deps for build (protobuf etc. optional)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git pkg-config build-essential protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Cache deps build
COPY Cargo.toml ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf target/release/deps/vrs_tss*

# Build actual binary
COPY src ./src

# COPY .env.example ./.env
# NOTE: no cache mount for /app/target
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release

FROM gcr.io/distroless/cc-debian12 AS runtime
COPY --from=builder /app/target/release/vrs-tss /usr/local/bin/vrs-tss
USER nonroot:nonroot
ENV IP=10.128.0.2
ENV PEER_ID=12D3KooWFcGs16mdf3HuNd2KMx5WYNsDyyDVz9h6Udg6WWg3CCxh
ENV NODE_DIR=/tmp/.tss_node
ENV PORT=8080
ENTRYPOINT ["/usr/local/bin/vrs-tss"]
