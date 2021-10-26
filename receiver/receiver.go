package receiver

import (
	"context"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"go.uber.org/zap"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/reflect/protoreflect"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"

	"github.com/isovalent/hubble-otel/common"
	"github.com/isovalent/hubble-otel/logs"
	"github.com/isovalent/hubble-otel/trace"
)

type hubbleReceiver struct {
	cfg    *Config
	ctx    context.Context
	cancel context.CancelFunc

	errs chan error

	zapLogger    *zap.Logger
	logrusLogger *logrus.Logger

	hubbleConn *grpc.ClientConn
}

type hubbleTracesReceiver struct {
	*hubbleReceiver
	consumer consumer.Traces
}

type hubbleLogsReceiver struct {
	*hubbleReceiver
	consumer consumer.Logs
}

func (r *hubbleReceiver) start() error {
	// custom backgorund context must be used for long-running tasks
	// (see https://github.com/open-telemetry/opentelemetry-collector/blob/v0.37.0/component/component.go#L41-L45)
	r.ctx, r.cancel = context.WithCancel(context.Background())

	tls, err := r.cfg.TLSClientSetting.LoadTLSConfig()
	if err != nil {
		return err
	}
	if tls != nil {
		r.hubbleConn, err = grpc.DialContext(r.ctx, r.cfg.Endpoint, grpc.WithTransportCredentials(credentials.NewTLS(tls)))
	} else {
		r.hubbleConn, err = grpc.DialContext(r.ctx, r.cfg.Endpoint, grpc.WithInsecure())
	}
	if err != nil {
		return fmt.Errorf("failed to connect to Hubble server: %w", err)
	}

	r.errs = make(chan error)

	return nil
}

func (r *hubbleReceiver) wait() error {
	for {
		select {
		case <-r.ctx.Done():
			return nil
		case err := <-r.errs:
			if err != nil {
				return fmt.Errorf("hubble reciever error: %w", err)
			}
		}
	}
}

func (r *hubbleReceiver) shutdown() error {
	r.cancel()
	_ = r.hubbleConn.Close()

	return nil
}

func (r *hubbleTracesReceiver) Start(_ context.Context, _ component.Host) error {
	if err := r.hubbleReceiver.start(); err != nil {
		return err
	}

	spanDB, err := os.MkdirTemp("", "hubble-otel-trace-cache-") // TODO: allow user to pass dir name for persistence
	if err != nil {
		return fmt.Errorf("failed to create temporary directory for span database: %w", err)
	}

	flowsToTraces := make(chan protoreflect.Message, r.cfg.BufferSize)

	converter, err := trace.NewFlowConverter(r.logrusLogger, spanDB, &r.cfg.FlowEncodingOptions.Traces)
	if err != nil {
		return fmt.Errorf("failed to create trace converter: %w", err)
	}

	go common.RunConverter(r.ctx, r.hubbleConn, converter, flowsToTraces, r.errs)

	exporter := trace.NewBufferedDirectTraceExporter(r.consumer, r.cfg.BufferSize)
	go common.RunExporter(r.ctx, r.logrusLogger, exporter, flowsToTraces, r.errs)

	return r.hubbleReceiver.wait()
}

func (r *hubbleTracesReceiver) Shutdown(_ context.Context) error {
	return r.hubbleReceiver.shutdown()
}

func (r *hubbleLogsReceiver) Start(_ context.Context, _ component.Host) error {
	if err := r.hubbleReceiver.start(); err != nil {
		return err
	}

	flowsToLogs := make(chan protoreflect.Message, r.cfg.BufferSize)

	converter := logs.NewFlowConverter(r.logrusLogger, &r.cfg.FlowEncodingOptions.Logs)
	go common.RunConverter(r.ctx, r.hubbleConn, converter, flowsToLogs, r.errs)

	exporter := logs.NewBufferedDirectLogsExporter(r.consumer, r.cfg.BufferSize)
	go common.RunExporter(r.ctx, r.logrusLogger, exporter, flowsToLogs, r.errs)

	return r.hubbleReceiver.wait()
}

func (r *hubbleLogsReceiver) Shutdown(_ context.Context) error {
	return r.hubbleReceiver.shutdown()
}
