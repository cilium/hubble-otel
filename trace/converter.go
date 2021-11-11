package trace

import (
	"time"

	"github.com/sirupsen/logrus"

	badger "github.com/dgraph-io/badger/v3"
	"go.opentelemetry.io/otel/trace"
	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	resourceV1 "go.opentelemetry.io/proto/otlp/resource/v1"
	traceV1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/reflect/protoreflect"

	flowV1 "github.com/cilium/cilium/api/v1/flow"
	hubbleObserver "github.com/cilium/cilium/api/v1/observer"

	"github.com/cilium/hubble-otel/common"
)

type FlowConverter struct {
	traceCache *TraceCache
	*common.FlowEncoder

	fallbackServiceName string
	parseHeaders        bool
}

func NewFlowConverter(
	log *logrus.Logger,
	dir string,
	options *common.EncodingOptions,
	includeFlowTypes *common.IncludeFlowTypes,
	fallbackServiceName string,
	traceCacheWindow time.Duration,
	parseHeaders bool,
) (*FlowConverter, error) {
	opt := badger.DefaultOptions(dir)
	opt.Logger = log
	tc, err := NewTraceCache(opt, traceCacheWindow)
	if err != nil {
		return nil, err
	}

	if log != nil {
		log.WithField("options", options.String()).Debugf("trace converter created")
	}

	return &FlowConverter{
		FlowEncoder: &common.FlowEncoder{
			EncodingOptions:  options,
			Logger:           log,
			IncludeFlowTypes: includeFlowTypes,
		},
		traceCache:          tc,
		fallbackServiceName: fallbackServiceName,
		parseHeaders:        parseHeaders,
	}, nil
}

func (c *FlowConverter) Convert(hubbleResp *hubbleObserver.GetFlowsResponse) (protoreflect.Message, error) {
	flow := hubbleResp.GetFlow()

	ctx, link, err := c.traceCache.GetSpanContext(flow, c.parseHeaders)
	if err != nil {
		return nil, err
	}

	spanID, traceID := getIDs(ctx)

	v, err := c.ToValue(hubbleResp)
	if err != nil {
		return nil, err
	}

	desc, err := c.getSpanDesc(hubbleResp)
	if err != nil {
		return nil, err
	}

	tsAsTime := flow.GetTime().AsTime()

	ts := uint64(tsAsTime.UnixNano())
	span := &traceV1.Span{
		Name: c.getSpanName(flow),
		// TODO: should ParentSpanId be resolved and set for reply packets?
		// (perhaps is is_reply and traffic_direction can be used for that)
		SpanId:            spanID,
		TraceId:           traceID,
		StartTimeUnixNano: ts,
		EndTimeUnixNano:   ts,
		Attributes: common.NewStringAttributes(map[string]string{
			common.AttributeEventKindVersion:     common.AttributeEventKindVersionFlowV1alpha1,
			common.AttributeEventEncoding:        c.EncodingFormat(),
			common.AttributeEventEncodingOptions: c.EncodingOptions.String(),
			common.AttributeEventDescription:     desc,
		}),
	}

	if link != nil {
		linkedSpanID, linkedTraceID := getIDs(link)
		span.Links = []*traceV1.Span_Link{{
			SpanId:  linkedSpanID,
			TraceId: linkedTraceID,
		}}
	}

	// TODO: optionally set Kind for TCP flows
	// via a user-settable peramater as it's
	// never clear-cut
	if l7 := flow.GetL7(); l7 != nil {
		switch l7.Type {
		case flowV1.L7FlowType_REQUEST:
			span.Kind = traceV1.Span_SPAN_KIND_CLIENT
		case flowV1.L7FlowType_RESPONSE:
			span.Kind = traceV1.Span_SPAN_KIND_SERVER
		}
		span.Attributes = append(span.Attributes, common.GetHTTPAttributes(l7)...)
	}

	if c.WithTopLevelKeys() {
		span.Attributes = append(span.Attributes, v.GetKvlistValue().Values...)
	} else {
		span.Attributes = append(span.Attributes, &commonV1.KeyValue{
			Key:   common.AttributeEventObject,
			Value: v,
		})
	}

	resourceSpans := &traceV1.ResourceSpans{
		Resource: &resourceV1.Resource{
			Attributes: common.GetAllResourceAttributes(flow, c.fallbackServiceName),
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

func getIDs(ctx *trace.SpanContext) ([]byte, []byte) {
	spanID := ctx.SpanID()
	traceID := ctx.TraceID()
	return spanID[:], traceID[:]
}
