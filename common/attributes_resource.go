package common

import (
	flowV1 "github.com/cilium/cilium/api/v1/flow"
	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
)

func GetAllResourceAttributes(flow *flowV1.Flow, fallbackServiceName string) (resourceAttributes []*commonV1.KeyValue) {
	resourceAttributes = append(resourceAttributes, GetServiceAttributes(flow, fallbackServiceName)...)
	resourceAttributes = append(resourceAttributes, GetKubernetesAttributes(flow)...)
	return
}
