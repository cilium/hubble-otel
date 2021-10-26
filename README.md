# Developer Documentation

This directory contains some script that are useful for testing `hubble-otel` in development.

Please note that general integrations tests for Hubble and OpenTelemetry collector are defined
in `main_test.go`, but scripts here are for manual testing with various exporters.

## Getting Started

First, one should install some of the key tools for development. Be sure you have latest version
of Go installed and know your `GOPATH`.

```
(cd tools ; go install github.com/cilium/mock-hubble github.com/open-telemetry/opentelemetry-collector-builder)
```

## Building Custom OpenTelemetry Collector

OpenTelemetry enables vendors to build custom collector binaries with their own plugins included.
For the purpose of testing logs exporters, and to enable exporting to various trace export from
a single collector build, there is a custom collector builder config in [`images/otelcol/builder.yaml`](images/otelcol/builder.yaml).

A custom collector is needed for testing all different exporters. There is a containerised build in
[`images/otelcol/Dockerfile`](images/otelcol/Dockerfile), but it's a bit easier to just run the collector
locally, especially as it's not OS-specific at all.

```
./dev-scripts/build-custom-otelcol.sh
```

The collector needs to be re-built whenever changes to `images/otelcol/builder.yaml` are made.

## Running Custom OpenTelemetry Collector

```
./dev-scripts/run-otelcol.sh
```

This will run a collector with a config featuring AWS XRay & CloudWatch exporters. An any other
config can used by passing `--config <path>` to the script.

This script doesn't do anything special, it's just a little bit convenient. Alternatively one
can just invoke the collector this way:

```
./dev-scripts/otelcol-custom/otelcol-custom  --config ./dev-scripts/export-aws.yaml
```

## Running Mock Hubble

For development, it's easier to run [a mock version of Hubble API](https://github.com/cilium/mock-hubble)
instead that produces a predictable stream of flows.

```
./dev-scripts/run-mock-hubble.sh
```

This script will run `mock-hubble` with a set of sample flows from `testdata` directory. It will replay the flows
as 10x the rate stored in the sample file. The sample file simply contains output of `hubble observe -o json -f`
and can be updated easily.

## Running `hubble-otel`

To run it agains a local collector:

```
./dev-script/run-hubble-otel.sh [<flags>]
```

This script is also only for convenience.
