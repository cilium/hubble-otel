#!/bin/bash -x

set -o errexit
set -o pipefail
set -o nounset

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

args=()
if [ "$#" -eq 0 ] ; then
  args=(--config "${script_dir}/export-aws.yaml")
else
  args=("$@")
fi

${script_dir}/otelcol-custom/otelcol-custom "${args[@]}"
