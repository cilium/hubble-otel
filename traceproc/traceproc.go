package traceproc

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/reflect/protoreflect"

	traceCollectorV1 "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	traceV1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

type BufferedTraceExporter struct {
	otlpLogs          traceCollectorV1.TraceServiceClient
	bufferSize        int
	headers           map[string]string
	exportCallOptions []grpc.CallOption
}

func NewBufferedTraceExporter(otlpConn *grpc.ClientConn, bufferSize int, headers map[string]string, callOptions ...grpc.CallOption) *BufferedTraceExporter {
	return &BufferedTraceExporter{
		otlpLogs:          traceCollectorV1.NewTraceServiceClient(otlpConn),
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
	_, err := s.otlpLogs.Export(ctx, &traceCollectorV1.ExportTraceServiceRequest{ResourceSpans: spans}, s.exportCallOptions...)
	return err
}
