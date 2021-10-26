# Copyright 2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

REGISTRY ?= ghcr.io/isovalent/hubble-otel

WITHOUT_TAG_SUFFIX ?= false
PUSH ?= false

GOBIN = $(shell go env GOPATH)/bin

IMAGINE ?= $(GOBIN)/imagine
KG ?= $(GOBIN)/kg

ifeq ($(MAKER_CONTAINER),true)
  IMAGINE=imagine
  KG=kg
endif

.buildx_builder:
	docker buildx create --platform linux/amd64 > $@

images.otelcol: .buildx_builder
	$(IMAGINE) build \
		--builder=$$(cat .buildx_builder) \
		--base=./ \
		--dockerfile=./images/otelcol/Dockerfile \
		--upstream-branch=origin/main \
		--name=otelcol \
		--registry=$(REGISTRY) \
		--without-tag-suffix=$(WITHOUT_TAG_SUFFIX) \
		--push=$(PUSH)
	$(IMAGINE) image \
		--base=./ \
		--upstream-branch=origin/main \
		--name=otelcol \
		--registry=$(REGISTRY) \
		--without-tag-suffix=$(WITHOUT_TAG_SUFFIX) \
		> image-otelcol.tag

images.hubble-otel: .buildx_builder
	$(IMAGINE) build \
		--builder=$$(cat .buildx_builder) \
		--base=./ \
		--upstream-branch=origin/main \
		--name=hubble-otel \
		--registry=$(REGISTRY) \
		--without-tag-suffix=$(WITHOUT_TAG_SUFFIX) \
		--push=$(PUSH)
	$(IMAGINE) image \
		--base=./ \
		--upstream-branch=origin/main \
		--name=hubble-otel \
		--registry=$(REGISTRY) \
		--without-tag-suffix=$(WITHOUT_TAG_SUFFIX) \
		> image-otelcol.tag
