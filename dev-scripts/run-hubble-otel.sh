#!/bin/bash -x

set -o errexit
set -o pipefail
set -o nounset

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

GOPATH="${GOPATH:-"${root_dir}/.gopath"}" go run main.go -bufferSize 24 -otlp.address localhost:55690 "$@"
