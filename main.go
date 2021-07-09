package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	logsCollectorV1 "github.com/isovalent/hubble-otel/internal/otlp/collector/logs/v1"
	commonV1 "github.com/isovalent/hubble-otel/internal/otlp/common/v1"
	logsV1 "github.com/isovalent/hubble-otel/internal/otlp/logs/v1"
	resourceV1 "github.com/isovalent/hubble-otel/internal/otlp/resource/v1"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
)

func main() {
	hubbleAddress := flag.String("hubbleAddress", "localhost:4245", "connect to Hubble on this address")
	otlpAddress := flag.String("otlpAddress", "", "connect to OTLP receiver on this address")

	logBufferSize := flag.Int("logBufferSize", 2048, "size of the buffer")

	flag.Parse()

	if err := run(*hubbleAddress, *otlpAddress, *logBufferSize); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run(hubbleAddress, otlpAddress string, logBufferSize int) error {
	ctx := context.Background()

	hubbleConn, err := grpc.DialContext(ctx, hubbleAddress, grpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("failed to connect to Hubble server: %w", err)
	}

	defer hubbleConn.Close()

	otlpConn, err := grpc.DialContext(ctx, otlpAddress, grpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("failed to connect to OTLP receiver: %w", err)
	}

	defer otlpConn.Close()

	flows := make(chan *logsV1.ResourceLogs, logBufferSize)

	errs := make(chan error)

	go logSender(ctx, otlpConn, logBufferSize, flows, errs)

	go flowReciever(ctx, hubbleConn, flows, errs)

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errs:
			if err != nil {
				return err
			}
		}
	}
}

func flowReciever(ctx context.Context, hubbleConn *grpc.ClientConn, flows chan<- *logsV1.ResourceLogs, errs chan<- error) {
	flowObsever, err := observer.NewObserverClient(hubbleConn).
		GetFlows(ctx, &observer.GetFlowsRequest{Follow: true})
	if err != nil {
		errs <- err
		return
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

		flows <- types.NewFlowLog(hubbleResp.GetFlow())
	}
}

func logSender(ctx context.Context, otlpConn *grpc.ClientConn, logBufferSize int, flows <-chan *logsV1.ResourceLogs, errs chan<- error) {
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
			fmt.Printf("wrote %d entries to the OTLP receiver\n", logBufferSize)
		default:
			if status.Code(err) == codes.Canceled {
				return
			}
			errs <- err
			return
		}
	}
}

const (
	FlowLogNameCiliumFlowV1Alpha1  = "cilium.flow_v1alpha1"
	FlowLogResourceCiliumClusterID = "cilium.cluster_id"
	FlowLogResourceCiliumNodeName  = "cilium.node_name"
)

func NewFlowLog(flow *flow.Flow) *logsV1.ResourceLogs {
	_ = commonV1.AnyValue{}
	return &logsV1.ResourceLogs{
		Resource: &resourceV1.Resource{
			Attributes: newStringAttributes(map[string]string{
				FlowLogResourceCiliumNodeName: flow.GetNodeName(),
			}),
		},
		InstrumentationLibraryLogs: []*logsV1.InstrumentationLibraryLogs{{
			Logs: []*logsV1.LogRecord{{
				TimeUnixNano: uint64(flow.GetTime().GetNanos()),
				Attributes:   newStringAttributes(map[string]string{}),
			}},
		}},
	}
}

func newStringAttributes(attributes map[string]string) []*commonV1.KeyValue {
	results := []*commonV1.KeyValue{}
	for k, v := range attributes {
		results = append(results, &commonV1.KeyValue{
			Key: k,
			Value: &commonV1.AnyValue{
				Value: &commonV1.AnyValue_StringValue{
					StringValue: v,
				},
			},
		})
	}
	return results
}
