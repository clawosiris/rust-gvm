# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.75.0

FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /workspace

COPY . .

RUN cargo build --locked --release -p gvm-mock-server \
    && strip target/release/gvm-mock-server

FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /workspace/target/release/gvm-mock-server /usr/local/bin/gvm-mock-server

ENTRYPOINT ["/usr/local/bin/gvm-mock-server"]
