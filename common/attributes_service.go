package common

import (
	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"

	flowV1 "github.com/cilium/cilium/api/v1/flow"
	hubbleLabels "github.com/cilium/hubble-ui/backend/domain/labels"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
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
		switch srcProps := hubbleLabels.Props(src.Labels) {
		case srcProps.AppName != nil:
			resourceAttributes[OTelAttrServiceName] = *srcProps.AppName
			resourceAttributes[OTelAttrServiceNamespace] = src.Namespace
		case srcProps.IsHost:
			resourceAttributes[OTelAttrServiceName] = fallbackServiceName + "-host"
		case srcProps.IsInit:
			resourceAttributes[OTelAttrServiceName] = fallbackServiceName + "-init"
		case srcProps.IsKubeDNS:
			resourceAttributes[OTelAttrServiceName] = fallbackServiceName + "-kube-dns"
		case srcProps.IsPrometheus:
			resourceAttributes[OTelAttrServiceName] = fallbackServiceName + "-prometheus"
		case srcProps.IsRemoteNode:
			resourceAttributes[OTelAttrServiceName] = fallbackServiceName + "-remote-node"
		case srcProps.IsWorld:
			resourceAttributes[OTelAttrServiceName] = fallbackServiceName + "-world"
		}
	}

	return NewStringAttributes(resourceAttributes)
}
