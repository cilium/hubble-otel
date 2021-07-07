module github.com/isovalent/otel-demo/hubble-otel

go 1.16

require (
	github.com/cilium/cilium v1.10.0
	github.com/open-telemetry/opentelemetry-log-collection v0.18.0
	go.opentelemetry.io/otel v0.20.0
	go.opentelemetry.io/otel/exporters/stdout v0.20.0
	go.opentelemetry.io/otel/metric v0.20.0
	go.opentelemetry.io/otel/trace v0.20.0
	go.uber.org/zap v1.16.0
	google.golang.org/grpc v1.38.0
)
