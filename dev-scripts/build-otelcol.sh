#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root_dir="$(cd "${script_dir}/.." && pwd)"

export GOPATH="${GOPATH:-"${root_dir}/.gopath"}"

${GOPATH}/bin/opentelemetry-collector-builder --config "${root_dir}/images/otelcol/builder.yaml" --output-path "${script_dir}/otelcol-hubble"
