# syntax=docker/dockerfile:1.7
#
# zvm-bridge: the peg daemon, the committee and its signers.
#
#   docker build -t zvm-bridge .
#
# Build from a checkout with its zvm-core submodule; the module's
# `replace ... => ./zvm-core` resolves inside the build context.

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY zvm-core/go.mod zvm-core/go.sum ./zvm-core/
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/zvm-bridge ./cmd/zvm-bridge

FROM alpine:3.22
RUN apk add --no-cache ca-certificates wget
COPY --from=build /out/zvm-bridge /usr/local/bin/zvm-bridge
ENTRYPOINT ["zvm-bridge"]
