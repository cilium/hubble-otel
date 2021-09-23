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
}

func NewFlowConverter(encoding string, options common.EncodingOptions) *FlowConverter {
	return &FlowConverter{
		FlowEncoder: &common.FlowEncoder{
			Encoding:        encoding,
			EncodingOptions: options,
		},
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
			common.AttributeEventKindVersion:     common.AttributeEventKindVersionFlowV1alpha1,
			common.AttributeEventEncoding:        c.Encoding,
			common.AttributeEventEncodingOptions: c.EncodingOptions.String(),
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

	if c.LogPayloadAsBody {
		if c.TopLevelKeys {
			for _, payloadAttribute := range v.GetKvlistValue().Values {
				logRecord.Attributes = append(logRecord.Attributes, payloadAttribute)
			}
		} else {
			logRecord.Attributes = append(logRecord.Attributes, &commonV1.KeyValue{
				Key:   common.AttributeEventPayload,
				Value: v,
			})
		}
	} else {
		logRecord.Body = v
	}

	return resourceLogs.ProtoReflect(), nil
}
