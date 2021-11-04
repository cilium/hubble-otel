module github.com/cilium/hubble-otel

go 1.16

require (
	github.com/cilium/cilium v1.10.4
	github.com/cilium/hubble v0.8.2
	github.com/cilium/mock-hubble v0.0.0-20211026154315-9c72b77d6839
	github.com/dgraph-io/badger/v3 v3.2103.0
	github.com/open-telemetry/opentelemetry-collector-contrib/exporter/prometheusexporter v0.38.0
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/translator/opencensus v0.38.0 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusreceiver v0.38.0
	github.com/prometheus/client_model v0.2.1-0.20200623203004-60555c9708c7
	github.com/prometheus/common v0.32.1
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	go.opentelemetry.io/collector v0.38.0
	go.opentelemetry.io/collector/model v0.38.0
	go.opentelemetry.io/contrib/propagators/aws v1.0.0
	go.opentelemetry.io/contrib/propagators/b3 v1.0.0
	go.opentelemetry.io/contrib/propagators/jaeger v1.0.0
	go.opentelemetry.io/contrib/propagators/ot v1.0.0
	go.opentelemetry.io/otel v1.0.1
	go.opentelemetry.io/otel/trace v1.0.1
	go.opentelemetry.io/proto/otlp v0.9.0
	google.golang.org/grpc v1.41.0
	google.golang.org/protobuf v1.27.1
)
