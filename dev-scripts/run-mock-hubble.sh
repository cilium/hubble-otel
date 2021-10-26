#!/bin/bash -x

set -o errexit
set -o pipefail
set -o nounset

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${root_dir}/tools" ; GOPATH="${GOPATH:-"${root_dir}/.gopath"}" go run github.com/cilium/mock-hubble -dir "${root_dir}/testdata/2021-10-04-sample-flows-istio-gke-l7" -rateAdjustment 10
