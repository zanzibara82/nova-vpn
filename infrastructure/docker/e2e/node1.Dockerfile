FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG AGENT_VERSION=dev
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath \
    -ldflags="-s -w -X main.version=${AGENT_VERSION}" \
    -o /out/novavpn-node-agent ./services/node-agent/cmd/novavpn-node-agent

FROM alpine:3.20
RUN apk add --no-cache ca-certificates unbound nftables iproute2 su-exec libcap wireguard-tools \
    && addgroup -g 65532 novavpn \
    && adduser -D -H -u 65532 -G novavpn novavpn \
    && mkdir -p /var/lib/novavpn-node /etc/novavpn \
    && chown 65532:65532 /var/lib/novavpn-node \
    && chmod 0700 /var/lib/novavpn-node
COPY --from=build /out/novavpn-node-agent /usr/local/bin/novavpn-node-agent
# Права на сокет netlink выдаются строго после COPY; подавлять ошибку нельзя.
RUN setcap cap_net_admin,cap_net_raw+ep /usr/local/bin/novavpn-node-agent
COPY infrastructure/docker/e2e/unbound.conf /etc/unbound/unbound.conf
COPY infrastructure/docker/e2e/nat.nft /etc/novavpn/nat.nft
COPY infrastructure/docker/e2e/node-entrypoint.sh /usr/local/bin/node-entrypoint.sh
RUN chmod 0755 /usr/local/bin/node-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/node-entrypoint.sh"]
CMD ["run"]