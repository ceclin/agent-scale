ARG TARGETARCH

FROM scratch AS control-amd64
COPY target/x86_64-unknown-linux-musl/release/as-control /as-control

FROM scratch AS control-arm64
COPY target/aarch64-unknown-linux-musl/release/as-control /as-control

FROM scratch AS relay-amd64
COPY target/x86_64-unknown-linux-musl/release/as-relay /as-relay

FROM scratch AS relay-arm64
COPY target/aarch64-unknown-linux-musl/release/as-relay /as-relay

FROM control-${TARGETARCH} AS control-binary

FROM alpine:3.22 AS control
RUN apk add --no-cache ca-certificates curl
COPY --from=control-binary /as-control /usr/local/bin/as-control
LABEL org.opencontainers.image.title="agent-scale control"

FROM relay-${TARGETARCH} AS relay-binary

FROM alpine:3.22 AS relay
RUN apk add --no-cache ca-certificates curl
COPY --from=relay-binary /as-relay /usr/local/bin/as-relay
LABEL org.opencontainers.image.title="agent-scale relay"
