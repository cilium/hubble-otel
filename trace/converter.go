package trace

import (
	"bytes"
	"strings"
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
	hubblePrinter "github.com/cilium/hubble/pkg/printer"

	"github.com/isovalent/hubble-otel/common"
)

type FlowConverter struct {
	traceCache *TraceCache
	*common.FlowEncoder
}

func NewFlowConverter(log *logrus.Logger, dir string, options *common.EncodingOptions) (*FlowConverter, error) {
	opt := badger.DefaultOptions(dir)
	opt.Logger = log
	tc, err := NewTraceCache(opt)
	if err != nil {
		return nil, err
	}

	if log != nil {
		log.WithField("options", options.String()).Debugf("trace converter created")
	}

	return &FlowConverter{
		FlowEncoder: &common.FlowEncoder{
			EncodingOptions: options,
			Logger:          log,
		},
		traceCache: tc,
	}, nil
}

func (c *FlowConverter) Convert(hubbleResp *hubbleObserver.GetFlowsResponse) (protoreflect.Message, error) {
	flow := hubbleResp.GetFlow()

	ctx, link, err := c.traceCache.GetSpanContext(flow)
	if err != nil {
		return nil, err
	}

	spanID, traceID := getIDs(ctx)

	v, err := c.ToValue(hubbleResp)
	if err != nil {
		return nil, err
	}

	name, err := c.getName(hubbleResp)
	if err != nil {
		return nil, err
	}

	tsAsTime := flow.GetTime().AsTime()

	ts := uint64(tsAsTime.UnixNano())
	span := &traceV1.Span{
		Name: name,
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

		span.EndTimeUnixNano = uint64(tsAsTime.Add(time.Duration(int64(l7.LatencyNs))).UnixNano())

		span.Attributes = append(span.Attributes, common.GetHTTPAttributes(l7)...)
	}

	if c.WithTopLevelKeys() {
		for _, payloadAttribute := range v.GetKvlistValue().Values {
			span.Attributes = append(span.Attributes, payloadAttribute)
		}
	} else {
		span.Attributes = append(span.Attributes, &commonV1.KeyValue{
			Key:   common.AttributeEventObject,
			Value: v,
		})
	}

	resourceSpans := &traceV1.ResourceSpans{
		Resource: &resourceV1.Resource{
			Attributes: common.GetKubernetesAttributes(flow),
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

func (c *FlowConverter) getName(hubbleResp *hubbleObserver.GetFlowsResponse) (string, error) {
	b := bytes.NewBuffer([]byte{})
	p := hubblePrinter.New(
		hubblePrinter.Writer(b),
		hubblePrinter.Compact(),
		hubblePrinter.WithTimeFormat(""),
		hubblePrinter.WithColor("never"),
		hubblePrinter.IgnoreStderr(),
	)
	if err := p.WriteProtoFlow(hubbleResp); err != nil {
		return "", err
	}
	s := strings.TrimSuffix(
		strings.TrimPrefix(b.String(), ": "),
		"\n",
	)
	return s, nil
}

func getIDs(ctx *trace.SpanContext) ([]byte, []byte) {
	spanID := ctx.SpanID()
	traceID := ctx.TraceID()
	return spanID[:], traceID[:]
}
