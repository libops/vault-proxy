FROM golang:1.25-alpine3.22@sha256:d3f0cf7723f3429e3f9ed846243970b20a2de7bae6a5b66fc5914e228d831bbb AS builder

SHELL ["/bin/ash", "-o", "pipefail", "-ex", "-c"]

WORKDIR /app

ARG \
    # renovate: datasource=repology depName=alpine_3_22/ca-certificates
    CA_CERTIFICATES_VERSION=20250911-r0 \
    # renovate: datasource=repology depName=alpine_3_22/dpkg
    DPKG_VERSION=1.22.15-r0 \
    # renovate: datasource=repology depName=alpine_3_22/gnupg
    GNUPG_VERSION=2.4.7-r0 \
    # renovate: datasource=github-releases depName=gosu packageName=tianon/gosu
    GOSU_VERSION=1.19

RUN apk add --no-cache --virtual .gosu-deps \
    ca-certificates=="${CA_CERTIFICATES_VERSION}" \
    dpkg=="${DPKG_VERSION}" \
    gnupg=="${GNUPG_VERSION}" && \
    dpkgArch="$(dpkg --print-architecture | awk -F- '{ print $NF }')" && \
    wget -q -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch" && \
    wget -q -O /usr/local/bin/gosu.asc "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch.asc" && \
    GNUPGHOME="$(mktemp -d)" && \
    export GNUPGHOME && \
    gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4 && \
    gpg --batch --verify /usr/local/bin/gosu.asc /usr/local/bin/gosu && \
    gpgconf --kill all && \
    rm -rf "$GNUPGHOME" /usr/local/bin/gosu.asc && \
    apk del --no-network .gosu-deps && \
    chmod +x /usr/local/bin/gosu && \
    echo "gosu install complete."

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY main.go ./

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -ldflags="-s -w" -o /app/vault-proxy .

FROM alpine:3.22

SHELL ["/bin/ash", "-o", "pipefail", "-c"]

ARG \
    # renovate: datasource=repology depName=alpine_3_22/curl
    CURL_VERSION=8.14.1-r2 \
    # renovate: datasource=repology depName=alpine_3_22/jq
    JQ_VERSION=1.8.1-r0


RUN apk add --no-cache \
    curl=="${CURL_VERSION}" \
    jq=="${JQ_VERSION}"

RUN adduser -S -G nobody -u 8080 vault-proxy

WORKDIR /app

COPY --from=builder /app/vault-proxy /app/vault-proxy
COPY --from=builder /usr/local/bin/gosu /usr/local/bin/gosu

EXPOSE 8080

ENTRYPOINT ["gosu", "vault-proxy", "/app/vault-proxy", "-config", "/app/config.yaml"]

HEALTHCHECK CMD curl -sf http://localhost:8080/v1/sys/health | jq .sealed | grep -q false
