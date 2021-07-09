package types

import (
	commonv1 "github.com/isovalent/hubble-otel/types/common/v1"
	logsv1 "github.com/isovalent/hubble-otel/types/logs/v1"
	resourcev1 "github.com/isovalent/hubble-otel/types/resource/v1"

	"github.com/cilium/cilium/api/v1/flow"
)

const (
	FlowLogNameCiliumFlowV1Alpha1  = "cilium.flow_v1alpha1"
	FlowLogResourceCiliumClusterID = "cilium.cluster_id"
	FlowLogResourceCiliumNodeName  = "cilium.node_name"
)

func NewFlowLog(flow *flow.Flow) *logsv1.ResourceLogs {
	_ = commonv1.AnyValue{}
	return &logsv1.ResourceLogs{
		Resource: &resourcev1.Resource{},
		// Timestamp: flow.Time.AsTime(),
		// Name:      FlowLogNameCiliumFlowV1Alpha1,
		// Attributes: []attribute.KeyValue{
		// 	attribute.Any(FlowLogNameCiliumFlowV1Alpha1, flow),
		// },
		// Resource: []attribute.KeyValue{
		// 	attribute.String(FlowLogResourceCiliumNodeName, flow.GetNodeName()),
		// },
	}
}
