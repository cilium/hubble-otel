package logconv

import (
	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsV1 "go.opentelemetry.io/proto/otlp/logs/v1"
	resourceV1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/cilium/cilium/api/v1/observer"
	"github.com/isovalent/hubble-otel/common"
)

type FlowConverter struct {
	*common.FlowEncoder
	UseAttributes bool
}

func NewFlowConverter(encoding string, useAttributes bool) *FlowConverter {
	return &FlowConverter{
		FlowEncoder: &common.FlowEncoder{
			Encoding: encoding,
		},
		UseAttributes: useAttributes,
	}
}
func (c *FlowConverter) Convert(hubbleResp *observer.GetFlowsResponse) (protoreflect.Message, error) {
	flow := hubbleResp.GetFlow()

	v, err := c.ToValue(hubbleResp)
	if err != nil {
		return nil, err
	}

	logRecord := &logsV1.LogRecord{
		TimeUnixNano: uint64(flow.GetTime().AsTime().UnixNano()),
		Attributes: common.NewStringAttributes(map[string]string{
			common.AttributeEventKindVersion: common.AttributeEventKindVersionFlowV1alpha1,
			common.AttributeEventEncoding:    c.Encoding,
		}),
	}

	resourceLogs := &logsV1.ResourceLogs{
		Resource: &resourceV1.Resource{
			Attributes: common.NewStringAttributes(map[string]string{
				common.ResourceCiliumNodeName: flow.GetNodeName(),
			}),
		},
		InstrumentationLibraryLogs: []*logsV1.InstrumentationLibraryLogs{{
			Logs: []*logsV1.LogRecord{logRecord},
		}},
	}

	if c.UseAttributes {
		logRecord.Attributes = append(logRecord.Attributes, &commonV1.KeyValue{
			Key:   common.AttributeEventPayload,
			Value: v,
		})
	} else {
		logRecord.Body = v
	}

	return resourceLogs.ProtoReflect(), nil
}
