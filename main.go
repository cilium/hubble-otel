package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/stdout"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/global"
	"go.opentelemetry.io/otel/trace"

	"github.com/cilium/cilium/api/v1/observer"

	// loggerOTEL "github.com/open-telemetry/opentelemetry-log-collection/logger"
	// "go.uber.org/zap"

	// "github.com/open-telemetry/opentelemetry-log-collection/entry"

	"github.com/isovalent/hubble-otel/types"

	otelLogs "github.com/open-telemetry/opentelemetry-proto/gen/go/logs/v1"
)

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	// zlogger, _ := zap.NewProduction()
	// defer zlogger.Sync()

	// logger := loggerOTEL.New(zlogger.Sugar())

	conn, err := grpc.DialContext(ctx, "localhost:4245", grpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("failed to connect to Hubble server: %w", err)
	}

	defer conn.Close()

	client := observer.NewObserverClient(conn)

	b, err := client.GetFlows(ctx, &observer.GetFlowsRequest{Follow: true})
	if err != nil {
		return err
	}

	tracer := otel.GetTracerProvider().Tracer(
		instrumentationName,
		trace.WithInstrumentationVersion(instrumentationVersion),
	)

	meter := global.GetMeterProvider().Meter(
		instrumentationName,
		metric.WithInstrumentationVersion(instrumentationVersion),
	)

	flowCounter := metric.Must(meter).NewInt64Counter("packets")

	exportOpts := []stdout.Option{
		stdout.WithPrettyPrint(),
	}

	// Registers both a trace and meter Provider globally.
	tracerProvider, pusher, err := stdout.InstallNewPipeline(exportOpts, nil)
	if err != nil {
		return fmt.Errorf("could not initialize stdout exporter: %w", err)
	}

	var span trace.Span

	// flows := make(chan entry.Entry)

	defer func() {
		_ = pusher.Stop(ctx)
		_ = tracerProvider.Shutdown(ctx)
	}()

	for {
		resp, err := b.Recv()
		switch err {
		case io.EOF, context.Canceled:
			return nil
		case nil:
		default:
			if status.Code(err) == codes.Canceled {
				return nil
			}
			return err
		}

		flow := resp.GetFlow()

		// fmt.Println(flow)
		// logger.Infow("new flow", "flow", flow)

		_ = types.NewFlowLog(flow)
		_ = &otelLogs.LogRecord{}

		ctx, span = tracer.Start(ctx, "flows")

		eventType := attribute.Key("CiliumEventType").String(flow.GetEventType().String())

		flowCounter.Add(ctx, 1, eventType)

		span.End()
	}
}

const (
	instrumentationName    = "github.com/instrumentron"
	instrumentationVersion = "v0.1.0"
)
