# syntax=docker/dockerfile:1.1-experimental

# Copyright 2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG GOLANG_IMAGE=docker.io/library/golang:1.16.6-alpine@sha256:bc2db47c5f4a682f1315e0d484811d65bf094d3bcd824459b170714c91656190
ARG CA_CERTIFICATES_IMAGE=docker.io/cilium/ca-certificates:69a9f5d66ff96bf97e8b9dc107e92aa9ddbdc9a8

FROM ${GOLANG_IMAGE} as builder

WORKDIR /src

RUN go install github.com/open-telemetry/opentelemetry-collector-builder@v0.33.0

RUN mkdir -p /out/usr/bin

RUN CGO_ENABLED=0 /go/bin/opentelemetry-collector-builder --output-path /out/usr/bin --config builder.yaml

FROM alpine
COPY --from=builder /out /out
ENTRYPOINT [ "/out/usr/bin/otelcol-custom" ]
