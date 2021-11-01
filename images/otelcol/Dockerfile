# syntax=docker/dockerfile:1.1-experimental

# Copyright 2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG GOLANG_IMAGE=docker.io/library/golang:1.17.1-alpine@sha256:13919fb9091f6667cb375d5fdf016ecd6d3a5d5995603000d422b04583de4ef9
ARG CA_CERTIFICATES_IMAGE=docker.io/cilium/ca-certificates:69a9f5d66ff96bf97e8b9dc107e92aa9ddbdc9a8

FROM ${GOLANG_IMAGE} as builder

ADD . /src

WORKDIR /src/tools
RUN go install go.opentelemetry.io/collector/cmd/builder

WORKDIR /src/images/otelcol
RUN CGO_ENABLED=0 /go/bin/builder --config ./builder.yaml --output-path ./

FROM alpine:3.13.6@sha256:d04f568d1401e6bcc2c34bd81ac1035ba1d8fc3a03b92c78e84cec61e028d6ea
COPY --from=builder /src/images/otelcol/otelcol-hubble /usr/bin
ENTRYPOINT [ "/usr/bin/otelcol-hubble" ]
