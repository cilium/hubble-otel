package common

import (
	"net/url"

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
		switch srcProps := hubbleLabels.Props(src.Labels); {
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
			// handle the case where pod name is known, but effective traffic source is world
			if serviceName := getServiceNameFromURL(flow); serviceName != "" {
				resourceAttributes[OTelAttrServiceName] = serviceName
			}
		}
	}

	return NewStringAttributes(resourceAttributes)
}

func getServiceNameFromURL(flow *flowV1.Flow) string {
	// there are cases where src.PodName could be set also,
	// but generally speaking it might just make sense to grab
	// the hostname from URL, it will also pickup internet
	// traffic also
	if l7 := flow.GetL7(); l7 != nil {
		if http := flow.GetL7().GetHttp(); http != nil {
			if u, err := url.Parse(http.Url); err == nil {
				return u.Hostname()
			}
		}
	}
	return ""
}
