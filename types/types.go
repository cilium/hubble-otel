package types

import (
	"github.com/cilium/cilium/api/v1/flow"
)

// FlowLog is an OpenTelemtery reprsentation of a Cilium flow
type FlowLog struct {
	Timestamp  time.Time         `json:"timestamp"`
	Name string `json:"name"`
	Attributes FlowLogAttributes `json:"attributes,omitempty"`
	Resource   FlowLogResources  `json:"resource,omitempty"`
}

type FlowLogAttributes struct {
	CiliumFlowV1 *flow.Flow `json:"cilium_flow_v1,omitempty"`
}

type FlowLogResources map[string]string

const (
	FlowLogNameCiliumFlowV1Alpha1 = "cilium.flow_v1alpha1"
	FlowLogResourceCiliumClusterID = "cilium.cluster_id"
	FlowLogResourceCiliumNodeName = "cilium.node_name"
)

func NewFlowLog(flow *flow.Flow) *FlowLog {
	return &FlowLog{
		Timestamp: flow.Timestamp,
		Name: FlowLogNameCiliumFlowV1Alpha1,
		Attributes: FlowLogAttributes{
			CiliumFlowV1: flow,
		},
		Resource: FlowLogResources{
			FlowLogResourceClusterID: flow.cluster_id,
		}
	}
}
