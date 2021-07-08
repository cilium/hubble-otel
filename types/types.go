package types

import (
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/cilium/cilium/api/v1/flow"
)

// FlowLog is an OpenTelemtery reprsentation of a Cilium flow
type FlowLog struct {
	Timestamp  time.Time            `json:"timestamp"`
	Name       string               `json:"name"`
	Attributes []attribute.KeyValue `json:"attributes,omitempty"`
	Resource   []attribute.KeyValue `json:"resource,omitempty"`
}

const (
	FlowLogNameCiliumFlowV1Alpha1  = "cilium.flow_v1alpha1"
	FlowLogResourceCiliumClusterID = "cilium.cluster_id"
	FlowLogResourceCiliumNodeName  = "cilium.node_name"
)

func NewFlowLog(flow *flow.Flow) *FlowLog {
	return &FlowLog{
		Timestamp: flow.Time.AsTime(),
		Name:      FlowLogNameCiliumFlowV1Alpha1,
		Attributes: []attribute.KeyValue{
			attribute.Any(FlowLogNameCiliumFlowV1Alpha1, flow),
		},
		Resource: []attribute.KeyValue{
			attribute.String(FlowLogResourceCiliumNodeName, flow.GetNodeName()),
		},
	}
}
