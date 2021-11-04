module github.com/cilium/hubble-otel/tools

go 1.16

require (
	github.com/cilium/mock-hubble v0.0.0-20211026154315-9c72b77d6839
	github.com/cloudflare/cfssl v1.6.1
	github.com/containerd/containerd v1.5.6 // indirect
	github.com/errordeveloper/imagine v0.0.0-20201215192748-b3494e82bc78
	go.opentelemetry.io/collector v0.38.0
	go.opentelemetry.io/collector/cmd/builder v0.0.0-20211103215828-cffbecb2ac9e
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
