module github.com/isovalent/hubble-otel

go 1.16

require (
	github.com/cloudflare/cfssl v1.6.0
	github.com/containerd/containerd v1.5.6 // indirect
	github.com/errordeveloper/imagine v0.0.0-20201215192748-b3494e82bc78
	github.com/isovalent/mock-hubble v0.0.0-20210928133358-8a1660dd0897
	github.com/open-telemetry/opentelemetry-collector-builder v0.33.0
)

// based on https://github.com/docker/buildx/blob/v0.5.1/go.mod#L61-L68

replace (
	// operator-registry: https://github.com/operator-framework/operator-registry/blob/v1.15.3/go.mod#L26
	github.com/golang/protobuf => github.com/golang/protobuf v1.4.2
	// protobuf: corresponds to containerd (through buildkit)
	// github.com/golang/protobuf => github.com/golang/protobuf v1.3.5
	github.com/jaguilar/vt100 => github.com/tonistiigi/vt100 v0.0.0-20190402012908-ad4c4a574305

	// genproto: corresponds to containerd (through buildkit)
	google.golang.org/genproto => google.golang.org/genproto v0.0.0-20200224152610-e50cd9704f63
)
