package logs

import (
	"github.com/sirupsen/logrus"

	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsV1 "go.opentelemetry.io/proto/otlp/logs/v1"
	resourceV1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/hubble-otel/common"
)

type FlowConverter struct {
	*common.FlowEncoder

	fallbackServiceNamePrefix string
}

func NewFlowConverter(
	log *logrus.Logger,
	options *common.EncodingOptions,
	includeFlowTypes *common.IncludeFlowTypes,
	fallbackServiceNamePrefix string,
) *FlowConverter {
	if log != nil {
		log.WithField("options", options.String()).Debugf("logs converter created")
	}

	return &FlowConverter{
		FlowEncoder: &common.FlowEncoder{
			EncodingOptions:  options,
			Logger:           log,
			IncludeFlowTypes: includeFlowTypes,
		},
		fallbackServiceNamePrefix: fallbackServiceNamePrefix,
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
			common.AttributeEventEncoding:        c.EncodingFormat(),
			common.AttributeEventEncodingOptions: c.EncodingOptions.String(),
		}),
	}

	if l7 := flow.GetL7(); l7 != nil {
		logRecord.Attributes = append(logRecord.Attributes, common.GetHTTPAttributes(l7)...)
	}

	resourceLogs := &logsV1.ResourceLogs{
		Resource: &resourceV1.Resource{
			Attributes: common.GetAllResourceAttributes(flow, c.fallbackServiceNamePrefix),
		},
		InstrumentationLibraryLogs: []*logsV1.InstrumentationLibraryLogs{{
			Logs: []*logsV1.LogRecord{logRecord},
		}},
	}

	if c.WithLogPayloadAsBody() {
		logRecord.Body = v
	} else if c.WithTopLevelKeys() {
		logRecord.Attributes = append(logRecord.Attributes, v.GetKvlistValue().Values...)
	} else {
		logRecord.Attributes = append(logRecord.Attributes, &commonV1.KeyValue{
			Key:   common.AttributeEventObject,
			Value: v,
		})
	}

	return resourceLogs.ProtoReflect(), nil
}
