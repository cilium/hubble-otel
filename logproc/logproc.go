package logproc

import (
	"context"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	logsCollectorV1 "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	logsV1 "go.opentelemetry.io/proto/otlp/logs/v1"

	"github.com/cilium/cilium/api/v1/observer"

	"github.com/isovalent/hubble-otel/logconv"
)

func FlowReciever(ctx context.Context, hubbleConn *grpc.ClientConn, encodingFormat string, useAttributes bool, flows chan<- *logsV1.ResourceLogs, errs chan<- error) {
	flowObsever, err := observer.NewObserverClient(hubbleConn).
		GetFlows(ctx, &observer.GetFlowsRequest{Follow: true})
	if err != nil {
		errs <- err
		return
	}

	c := logconv.FlowConverter{
		Encoding:      encodingFormat,
		UseAttributes: useAttributes,
	}

	for {
		hubbleResp, err := flowObsever.Recv()
		switch err {
		case io.EOF, context.Canceled:
			return
		case nil:
		default:
			if status.Code(err) == codes.Canceled {
				return
			}
			errs <- err
			return
		}

		flow, err := c.Convert(hubbleResp)
		if err != nil {
			errs <- err
			return
		}
		flows <- flow
	}
}

func LogSender(ctx context.Context, otlpConn *grpc.ClientConn, logBufferSize int, flows <-chan *logsV1.ResourceLogs, errs chan<- error) {
	otlpLogs := logsCollectorV1.NewLogsServiceClient(otlpConn)

	for {
		logs := make([]*logsV1.ResourceLogs, logBufferSize)

		for i := range logs {
			logs[i] = <-flows
		}

		_, err := otlpLogs.Export(ctx, &logsCollectorV1.ExportLogsServiceRequest{ResourceLogs: logs})
		switch err {
		case io.EOF, context.Canceled:
			return
		case nil:
			// fmt.Printf("wrote %d entries to the OTLP receiver\n", logBufferSize)
			continue
		default:
			if status.Code(err) == codes.Canceled {
				return
			}
			errs <- err
			return
		}
	}
}
