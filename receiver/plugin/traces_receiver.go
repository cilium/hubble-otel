package hubblereceiver

import (
	"context"
	"fmt"
	"os"

	"github.com/isovalent/hubble-otel/receiver"
	"github.com/isovalent/hubble-otel/sender"
	"github.com/isovalent/hubble-otel/traceconv"
	"github.com/isovalent/hubble-otel/traceproc"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/reflect/protoreflect"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
)

type hubbleReceiver struct {
	cfg        *Config
	consumer   consumer.Traces
	ctx        context.Context
	cancelFunc context.CancelFunc

	logger *zap.Logger

	hubbleConn *grpc.ClientConn
}

type hubbleTracesReceiver struct {
	hubbleReceiver
}

func (r *hubbleReceiver) start() error {
	r.ctx, r.cancelFunc = context.WithCancel(context.Background())

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

	return nil
}

func (r *hubbleReceiver) shutdown() error {
	r.cancelFunc()
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

	errs := make(chan error)
	flowsToTraces := make(chan protoreflect.Message, r.cfg.BufferSize)

	log := logrus.New() // TODO: ensure this actually logs via zap

	traceConverter, err := traceconv.NewFlowConverter(log, spanDB, &r.cfg.FlowEncodingOptions.Traces)
	if err != nil {
		return fmt.Errorf("failed to create trace converter: %w", err)
	}

	go receiver.Run(r.ctx, r.hubbleConn, traceConverter, flowsToTraces, errs)

	exporter := traceproc.NewBufferedDirectTraceExporter(r.consumer, r.cfg.BufferSize)
	go sender.Run(r.ctx, log, exporter, flowsToTraces, errs)

	for {
		select {
		case <-r.ctx.Done():
			return nil
		case err := <-errs:
			if err != nil {
				return err
			}
		}
	}

}

func (r *hubbleTracesReceiver) Shutdown(_ context.Context) error {
	return r.hubbleReceiver.shutdown()
}
