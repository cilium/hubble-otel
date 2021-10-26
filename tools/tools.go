//go:build tools

package tools

import (
	_ "github.com/cilium/mock-hubble"
	_ "github.com/cloudflare/cfssl/cmd/cfssl"
	_ "github.com/cloudflare/cfssl/cmd/cfssljson"
	_ "github.com/errordeveloper/imagine"
	_ "github.com/open-telemetry/opentelemetry-collector-builder"
	_ "go.opentelemetry.io/collector/cmd/otelcol"
)
