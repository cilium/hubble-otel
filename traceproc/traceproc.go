package traceproc

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/reflect/protoreflect"

	traceCollectorV1 "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	traceV1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

type BufferedTraceExporter struct {
	otlpLogs   traceCollectorV1.TraceServiceClient
	bufferSize int
}

func NewBufferedTraceExporter(otlpConn *grpc.ClientConn, bufferSize int) *BufferedTraceExporter {
	return &BufferedTraceExporter{
		otlpLogs:   traceCollectorV1.NewTraceServiceClient(otlpConn),
		bufferSize: bufferSize,
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

	_, err := s.otlpLogs.Export(ctx, &traceCollectorV1.ExportTraceServiceRequest{ResourceSpans: spans})
	return err
}
