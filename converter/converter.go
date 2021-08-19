package converter

import (
	"encoding/base64"

	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsV1 "go.opentelemetry.io/proto/otlp/logs/v1"
	resourceV1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/cilium/cilium/api/v1/observer"
	// "github.com/cilium/cilium/api/v1/flow"
)

const (
	keyPrefix = "io.cilium.otel."

	FlowLogAttributeLogKindVersion             = keyPrefix + "log_kind_version"
	FlowLogAttributeLogKindVersionFlowV1alpha1 = "flow/v1alpha1"
	FlowLogAttributeLogEncoding                = keyPrefix + "log_encoding"
	FlowLogEncodingJSON                        = "JSON"
	FlowLogEncodingJSONBASE64                  = "JSON+base64"
	FlowLogEncodingKeyedList                   = "keyedlist"

	FlowLogResourceCiliumClusterID = keyPrefix + "cluster_id"
	FlowLogResourceCiliumNodeName  = keyPrefix + "node_name"
)

type FlowConverter struct {
	Encoding string
}

func (c *FlowConverter) Convert(hubbleResp *observer.GetFlowsResponse) (*logsV1.ResourceLogs, error) {

	// TODO: efficiency considerations
	// - store JSON as bytes or keep it as a string?
	// - can raw flow protobuf be extracted from the observer.GetFlowsResponse envelope? it maybe more efficient...
	// - what about ecoding to nested commonV1.KeyValueList structure instead of JSON?
	//   - it maybe an option to encode into a flat map with keys being JSON paths
	// - should encoding be user-settable?

	flow := hubbleResp.GetFlow()

	body, err := c.body(hubbleResp)
	if err != nil {
		return nil, err
	}

	return &logsV1.ResourceLogs{
		Resource: &resourceV1.Resource{
			Attributes: newStringAttributes(map[string]string{
				FlowLogResourceCiliumNodeName: flow.GetNodeName(),
			}),
		},
		InstrumentationLibraryLogs: []*logsV1.InstrumentationLibraryLogs{{
			Logs: []*logsV1.LogRecord{{
				TimeUnixNano: uint64(flow.GetTime().AsTime().UnixNano()),
				Attributes: newStringAttributes(map[string]string{
					FlowLogAttributeLogKindVersion: FlowLogAttributeLogKindVersionFlowV1alpha1,
					FlowLogAttributeLogEncoding:    c.Encoding,
				}),
				Body: body,
			}},
		}},
	}, nil
}

func (c *FlowConverter) body(hubbleResp *observer.GetFlowsResponse) (*commonV1.AnyValue, error) {
	var (
		data []byte
		err  error
		v    *commonV1.AnyValue
	)

	switch c.Encoding {
	case FlowLogEncodingJSON, FlowLogEncodingJSONBASE64:
		data, err = hubbleResp.GetFlow().MarshalJSON()
		if err != nil {
			return nil, err
		}

		var s string
		switch c.Encoding {
		case FlowLogEncodingJSON:
			s = string(data)
		case FlowLogEncodingJSONBASE64:
			s = base64.RawStdEncoding.EncodeToString(data)
		}

		v = &commonV1.AnyValue{
			Value: &commonV1.AnyValue_StringValue{
				StringValue: s,
			},
		}
	case FlowLogEncodingKeyedList:
		l := []*commonV1.KeyValue{}

		hubbleResp.GetFlow().ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
			l = append(l, &commonV1.KeyValue{
				Key: fd.JSONName(),
			})
			return true
		})

		v = &commonV1.AnyValue{
			Value: &commonV1.AnyValue_KvlistValue{
				KvlistValue: &commonV1.KeyValueList{
					Values: l,
				},
			},
		}
	}

	return v, nil
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
