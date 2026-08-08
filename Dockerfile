FROM alpine:3.22

ARG RUST_TARGET=x86_64-unknown-linux-musl
RUN apk add --no-cache ca-certificates curl
COPY target/${RUST_TARGET}/release/as-control /usr/local/bin/as-control
COPY target/${RUST_TARGET}/release/as-relay /usr/local/bin/as-relay

LABEL org.opencontainers.image.title="agent-scale control and relay"
