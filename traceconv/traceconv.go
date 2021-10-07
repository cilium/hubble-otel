package traceconv

import (
	"bytes"
	"strings"

	"github.com/sirupsen/logrus"

	badger "github.com/dgraph-io/badger/v3"
	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	resourceV1 "go.opentelemetry.io/proto/otlp/resource/v1"
	traceV1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/reflect/protoreflect"

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

	ids, err := c.traceCache.GetIDs(flow)
	if err != nil {
		return nil, err
	}

	v, err := c.ToValue(hubbleResp)
	if err != nil {
		return nil, err
	}

	name, err := c.getName(hubbleResp)
	if err != nil {
		return nil, err
	}

	ts := uint64(flow.GetTime().AsTime().UnixNano())
	span := &traceV1.Span{
		Name: name,
		// TODO: should ParentSpanId be resolved and set for reply packets?
		SpanId:            ids.SpanID[:],
		TraceId:           ids.TraceID[:],
		StartTimeUnixNano: ts,
		EndTimeUnixNano:   ts,
		// TODO: optionally set Kind for TCP flows via a user-settable peramater
		Attributes: common.NewStringAttributes(map[string]string{
			common.AttributeEventKindVersion:     common.AttributeEventKindVersionFlowV1alpha1,
			common.AttributeEventEncoding:        c.EncodingFormat(),
			common.AttributeEventEncodingOptions: c.EncodingOptions.String(),
		}),
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
