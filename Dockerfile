# syntax=docker/dockerfile:1.1-experimental

# Copyright 2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG GOLANG_IMAGE=docker.io/library/golang:1.17.1-alpine@sha256:13919fb9091f6667cb375d5fdf016ecd6d3a5d5995603000d422b04583de4ef9
ARG CA_CERTIFICATES_IMAGE=docker.io/cilium/ca-certificates:69a9f5d66ff96bf97e8b9dc107e92aa9ddbdc9a8

FROM ${GOLANG_IMAGE} as builder

WORKDIR /src
ENV GOPRIVATE=github.com/isovalent

RUN mkdir -p /out/usr/bin

RUN --mount=type=bind,target=/src --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -ldflags '-s -w' -o /out/usr/bin/hubble-otel ./

FROM ${CA_CERTIFICATES_IMAGE}
COPY --from=builder /out /

ENTRYPOINT ["/usr/bin/hubble-otel"]
