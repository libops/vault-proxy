FROM ghcr.io/libops/go:1.26.5@sha256:ea764e85e42a243217c621891123b3fda9374674c29d59785414fc6b15815b3d AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && \
    go mod verify

COPY main.go ./

ARG TARGETOS=linux
ARG TARGETARCH
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -buildvcs=false -trimpath -ldflags="-s -w" -o /out/vault-proxy .

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/vault-proxy /vault-proxy

USER 65532:65532
EXPOSE 8080

ENTRYPOINT ["/vault-proxy"]
