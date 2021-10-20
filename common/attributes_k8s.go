package common

import (
	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"

	flowV1 "github.com/cilium/cilium/api/v1/flow"
)

const (
	OTelAttrK8sNodeName      = "k8s.node.name"
	OTelAttrK8sNamespaceName = "k8s.namespace.name"
	OTelAttrK8sPodName       = "k8s.pod.name"
)

func GetKubernetesAttributes(flow *flowV1.Flow) []*commonV1.KeyValue {
	resourceAttributes := map[string]string{
		OTelAttrK8sNodeName: flow.GetNodeName(),
	}

	if src := flow.Source; src != nil {
		if src.Namespace != "" {
			resourceAttributes[OTelAttrK8sNamespaceName] = src.Namespace
		}
		if src.PodName != "" {
			resourceAttributes[OTelAttrK8sPodName] = src.PodName
		}
	}

	return NewStringAttributes(resourceAttributes)
}
