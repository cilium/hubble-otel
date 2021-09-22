package logproc

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/reflect/protoreflect"

	logsCollectorV1 "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	logsV1 "go.opentelemetry.io/proto/otlp/logs/v1"
)

type BufferedLogExporter struct {
	otlpLogs          logsCollectorV1.LogsServiceClient
	bufferSize        int
	headers           map[string]string
	exportCallOptions []grpc.CallOption
}

func NewBufferedLogExporter(otlpConn *grpc.ClientConn, bufferSize int, headers map[string]string, callOptions ...grpc.CallOption) *BufferedLogExporter {
	return &BufferedLogExporter{
		otlpLogs:          logsCollectorV1.NewLogsServiceClient(otlpConn),
		bufferSize:        bufferSize,
		exportCallOptions: callOptions,
	}
}

func (s *BufferedLogExporter) Export(ctx context.Context, flows <-chan protoreflect.Message) error {
	logs := make([]*logsV1.ResourceLogs, s.bufferSize)

	for i := range logs {
		flow, ok := (<-flows).Interface().(*logsV1.ResourceLogs)
		if !ok {
			return fmt.Errorf("cannot convert protoreflect.Message to logsV1.ResourceLogs")
		}
		logs[i] = flow
	}

	if s.headers != nil {
		ctx = metadata.NewOutgoingContext(ctx, metadata.New(s.headers))
	}
	_, err := s.otlpLogs.Export(ctx, &logsCollectorV1.ExportLogsServiceRequest{ResourceLogs: logs}, s.exportCallOptions...)
	return err
}
