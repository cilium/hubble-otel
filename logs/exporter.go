package logs

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/model/otlp"
	"go.opentelemetry.io/collector/model/pdata"

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

type BufferedDirectLogsExporter struct {
	log         *logrus.Logger
	consumer    consumer.Logs
	bufferSize  int
	unmarshaler pdata.LogsUnmarshaler
}

func NewBufferedDirectLogsExporter(log *logrus.Logger, consumer consumer.Logs, bufferSize int) *BufferedDirectLogsExporter {
	return &BufferedDirectLogsExporter{
		log:         log,
		consumer:    consumer,
		bufferSize:  bufferSize,
		unmarshaler: otlp.NewProtobufLogsUnmarshaler(),
	}
}

func (s *BufferedDirectLogsExporter) Export(ctx context.Context, flows <-chan protoreflect.Message) error {
	logs := make([]*logsV1.ResourceLogs, s.bufferSize)

	for i := range logs {
		flow, ok := (<-flows).Interface().(*logsV1.ResourceLogs)
		if !ok {
			return fmt.Errorf("cannot convert protoreflect.Message to logsV1.ResourceLogs")
		}
		logs[i] = flow
	}

	// there is no clear way of converting public Go types (go.opentelemetry.io/proto/otlp)
	// and internal collector types (go.opentelemetry.io/collector/model);
	// see https://github.com/open-telemetry/opentelemetry-collector/issues/4254
	data, err := proto.Marshal(&logsCollectorV1.ExportLogsServiceRequest{ResourceLogs: logs})
	if err != nil {
		return fmt.Errorf("cannot marshal lgs: %w", err)
	}
	unmarshalledLogs, err := s.unmarshaler.UnmarshalLogs(data)
	if err != nil {
		return fmt.Errorf("cannot unmarshal logs: %w", err)
	}

	s.log.Debug("flushing log buffer to the consumer")
	return s.consumer.ConsumeLogs(ctx, unmarshalledLogs)
}
