package types

import (
	commonV1 "github.com/isovalent/hubble-otel/types/common/v1"
	logsV1 "github.com/isovalent/hubble-otel/types/logs/v1"
	resourceV1 "github.com/isovalent/hubble-otel/types/resource/v1"

	"github.com/cilium/cilium/api/v1/flow"
)

const (
	FlowLogNameCiliumFlowV1Alpha1  = "cilium.flow_v1alpha1"
	FlowLogResourceCiliumClusterID = "cilium.cluster_id"
	FlowLogResourceCiliumNodeName  = "cilium.node_name"
)

func NewFlowLog(flow *flow.Flow) *logsV1.ResourceLogs {
	_ = commonV1.AnyValue{}
	return &logsV1.ResourceLogs{
		Resource: &resourceV1.Resource{
			Attributes: newStringAttributes(map[string]string{
				FlowLogResourceCiliumNodeName: flow.GetNodeName(),
			}),
		},
		InstrumentationLibraryLogs: []*logsV1.InstrumentationLibraryLogs{{
			Logs: []*logsV1.LogRecord{{
				TimeUnixNano: uint64(flow.GetTime().GetNanos()),
				Attributes:   newStringAttributes(map[string]string{}),
			}},
		}},
	}
}

func newStringAttributes(attributes map[string]string) []*commonV1.KeyValue {
	results := []*commonV1.KeyValue{}
	for k, v := range attributes {
		results = append(results, &commonV1.KeyValue{
			Key: k,
			Value: &commonV1.AnyValue{
				Value: &commonV1.AnyValue_StringValue{
					StringValue: v,
				},
			},
		})
	}
	return results
}
