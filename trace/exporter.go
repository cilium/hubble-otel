package trace

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/model/otlp"
	"go.opentelemetry.io/collector/model/pdata"

	traceCollectorV1 "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	traceV1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

type BufferedTraceExporter struct {
	otlpTrace         traceCollectorV1.TraceServiceClient
	bufferSize        int
	headers           map[string]string
	exportCallOptions []grpc.CallOption
}

func NewBufferedTraceExporter(otlpConn *grpc.ClientConn, bufferSize int, headers map[string]string, callOptions ...grpc.CallOption) *BufferedTraceExporter {
	return &BufferedTraceExporter{
		otlpTrace:         traceCollectorV1.NewTraceServiceClient(otlpConn),
		bufferSize:        bufferSize,
		headers:           headers,
		exportCallOptions: callOptions,
	}
}

func (s *BufferedTraceExporter) Export(ctx context.Context, flows <-chan protoreflect.Message) error {
	spans := make([]*traceV1.ResourceSpans, s.bufferSize)

	for i := range spans {
		flow, ok := (<-flows).Interface().(*traceV1.ResourceSpans)
		if !ok {
			return fmt.Errorf("cannot convert protoreflect.Message to traceV1.ResourceSpans")
		}
		spans[i] = flow
	}

	if s.headers != nil {
		ctx = metadata.NewOutgoingContext(ctx, metadata.New(s.headers))
	}
	_, err := s.otlpTrace.Export(ctx, &traceCollectorV1.ExportTraceServiceRequest{ResourceSpans: spans}, s.exportCallOptions...)
	return err
}

type BufferedDirectTraceExporter struct {
	consumer          consumer.Traces
	bufferSize        int
	tracesMarshaler   pdata.TracesMarshaler
	tracesUnmarshaler pdata.TracesUnmarshaler
}

func NewBufferedDirectTraceExporter(consumer consumer.Traces, bufferSize int) *BufferedDirectTraceExporter {
	return &BufferedDirectTraceExporter{
		consumer:          consumer,
		bufferSize:        bufferSize,
		tracesUnmarshaler: otlp.NewProtobufTracesUnmarshaler(),
	}
}

func (s *BufferedDirectTraceExporter) Export(ctx context.Context, flows <-chan protoreflect.Message) error {
	spans := make([]*traceV1.ResourceSpans, s.bufferSize)

	for i := range spans {
		flow, ok := (<-flows).Interface().(*traceV1.ResourceSpans)
		if !ok {
			return fmt.Errorf("cannot convert protoreflect.Message to traceV1.ResourceSpans")
		}
		spans[i] = flow
	}

	// there is no clear way of converting public Go types (go.opentelemetry.io/proto/otlp)
	// and internal collector types (go.opentelemetry.io/collector/model);
	// see https://github.com/open-telemetry/opentelemetry-collector/issues/4254
	data, err := proto.Marshal(&traceCollectorV1.ExportTraceServiceRequest{ResourceSpans: spans})
	if err != nil {
		return fmt.Errorf("cannot marshal traces: %w", err)
	}
	traces, err := s.tracesUnmarshaler.UnmarshalTraces(data)
	if err != nil {
		return fmt.Errorf("cannot unmarshal traces: %w", err)
	}

	return s.consumer.ConsumeTraces(ctx, traces)
}
