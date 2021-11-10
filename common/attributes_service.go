package common

import (
	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"

	flowV1 "github.com/cilium/cilium/api/v1/flow"
	hubbleLabels "github.com/cilium/hubble-ui/backend/domain/labels"
)

const (
	OTelAttrServiceName      = "service.name"
	OTelAttrServiceNamespace = "service.namespace"

	OTelAttrServiceNameDefault = "hubble-otel"
)

func GetServiceAttributes(flow *flowV1.Flow, fallbackServiceName string) []*commonV1.KeyValue {
	resourceAttributes := map[string]string{
		OTelAttrServiceName: fallbackServiceName,
	}

	if src := flow.Source; src != nil {
		srcProps := hubbleLabels.Props(src.Labels)
		if srcProps.AppName != nil {
			resourceAttributes[OTelAttrServiceName] = *srcProps.AppName
			resourceAttributes[OTelAttrServiceNamespace] = src.Namespace
		}
	}

	return NewStringAttributes(resourceAttributes)
}
