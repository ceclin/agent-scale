ARG TARGETARCH

FROM scratch AS control-amd64
COPY target/container-root/bin/as-control-amd64 /as-control

FROM scratch AS control-arm64
COPY target/container-root/bin/as-control-arm64 /as-control

FROM scratch AS relay-amd64
COPY target/container-root/bin/as-relay-amd64 /as-relay

FROM scratch AS relay-arm64
COPY target/container-root/bin/as-relay-arm64 /as-relay

FROM control-${TARGETARCH} AS control-binary

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce AS control
RUN apk add --no-cache ca-certificates curl
COPY --chmod=0755 --from=control-binary /as-control /usr/local/bin/as-control
COPY LICENSE /usr/share/licenses/agent-scale/LICENSE
COPY licenses/dependencies/as-control.html /usr/share/licenses/agent-scale/THIRD_PARTY_LICENSES.html
LABEL org.opencontainers.image.title="agent-scale control"

FROM relay-${TARGETARCH} AS relay-binary

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce AS relay
RUN apk add --no-cache ca-certificates curl
COPY --chmod=0755 --from=relay-binary /as-relay /usr/local/bin/as-relay
COPY LICENSE /usr/share/licenses/agent-scale/LICENSE
COPY licenses/dependencies/as-relay.html /usr/share/licenses/agent-scale/THIRD_PARTY_LICENSES.html
LABEL org.opencontainers.image.title="agent-scale relay"
