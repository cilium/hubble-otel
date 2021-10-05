module github.com/isovalent/hubble-otel

go 1.16

require (
	github.com/cilium/cilium v1.10.4
	github.com/cilium/hubble v0.8.2
	github.com/dgraph-io/badger/v3 v3.2103.0
	github.com/isovalent/mock-hubble v0.0.0-20210928133358-8a1660dd0897
	github.com/open-telemetry/opentelemetry-collector-contrib/exporter/prometheusexporter v0.36.0
	github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusreceiver v0.36.0
	github.com/prometheus/client_model v0.2.1-0.20200623203004-60555c9708c7
	github.com/prometheus/common v0.30.0
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	go.opentelemetry.io/collector v0.36.0
	go.opentelemetry.io/otel/sdk v1.0.1 // indirect
	go.opentelemetry.io/otel/trace v1.0.1
	go.opentelemetry.io/proto/otlp v0.9.0
	google.golang.org/grpc v1.40.0
	google.golang.org/protobuf v1.27.1
)
