FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath -ldflags="-s -w" \
    -o /out/probe ./tests/e2e/probe

FROM alpine:3.20
RUN apk add --no-cache dnsmasq
COPY --from=build /out/probe /usr/local/bin/probe
COPY infrastructure/docker/e2e/dnsmasq.conf /etc/dnsmasq.conf
ENTRYPOINT ["/bin/sh", "-c", "dnsmasq --conf-file=/etc/dnsmasq.conf && exec /usr/local/bin/probe"]