//go:build tools

package tools

import (
	_ "github.com/cloudflare/cfssl/cmd/cfssl"
	_ "github.com/cloudflare/cfssl/cmd/cfssljson"
	_ "github.com/isovalent/mock-hubble/server"
	_ "github.com/open-telemetry/opentelemetry-collector-builder"
	_ "go.opentelemetry.io/collector/cmd/otelcol"
)
