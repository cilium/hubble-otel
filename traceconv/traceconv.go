package traceconv

import (
	badger "github.com/dgraph-io/badger/v3"
	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	resourceV1 "go.opentelemetry.io/proto/otlp/resource/v1"
	traceV1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/cilium/cilium/api/v1/observer"
	"github.com/isovalent/hubble-otel/common"
)

type FlowConverter struct {
	traceCache *TraceCache
	*common.FlowEncoder
}

func NewFlowConverter(attributeEncoding, dir string) (*FlowConverter, error) {
	opt := badger.DefaultOptions(dir)
	opt.Logger = nil // TODO: make this use hubble-otel logger
	tc, err := NewTraceCache(opt)
	if err != nil {
		return nil, err
	}
	return &FlowConverter{
		FlowEncoder: &common.FlowEncoder{
			Encoding: attributeEncoding,
		},
		traceCache: tc,
	}, nil
}

func (c *FlowConverter) Convert(hubbleResp *observer.GetFlowsResponse) (protoreflect.Message, error) {
	flow := hubbleResp.GetFlow()

	traceID, spanID, err := c.traceCache.GetIDs(flow)
	if err != nil {
		return nil, err
	}

	v, err := c.ToValue(hubbleResp)
	if err != nil {
		return nil, err
	}

	ts := uint64(flow.GetTime().AsTime().UnixNano())
	span := &traceV1.Span{
		// TODO: should ParentSpanId be resolved and set for reply packets?
		SpanId:            spanID[:],
		TraceId:           traceID[:],
		StartTimeUnixNano: ts,
		EndTimeUnixNano:   ts,
		// TODO: optionally set Kind for TCP flows via a user-settable peramater
		Attributes: common.NewStringAttributes(map[string]string{
			common.AttributeEventKindVersion: common.AttributeEventKindVersionFlowV1alpha1,
			common.AttributeEventEncoding:    c.Encoding,
		}),
	}
	span.Attributes = append(span.Attributes, &commonV1.KeyValue{
		Key:   common.AttributeEventPayload,
		Value: v,
	})
	resourceSpans := &traceV1.ResourceSpans{
		Resource: &resourceV1.Resource{
			Attributes: common.NewStringAttributes(map[string]string{
				common.ResourceCiliumNodeName: flow.GetNodeName(),
			}),
		},
		InstrumentationLibrarySpans: []*traceV1.InstrumentationLibrarySpans{{
			Spans: []*traceV1.Span{span},
		}},
	}

	return resourceSpans.ProtoReflect(), nil
}

func (c *FlowConverter) CloseCache() error {
	return c.traceCache.Close()
}

func (c *FlowConverter) DeleteCache() {
	c.traceCache.Delete()
}
