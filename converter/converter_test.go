package converter_test

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	logsV1 "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/grpc"

	"github.com/isovalent/hubble-otel/converter"
	"github.com/isovalent/hubble-otel/processors"
	"github.com/isovalent/hubble-otel/testutils"
)

const (
	hubbleAddress = "localhost:4245"
	logBufferSize = 2048
)

func BenchmarkAllModes(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fatal := make(chan error, 1)

	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	go testutils.RunMockHubble(ctx, log, "../testdata/2021-06-16-sample-flows-istio-gke", hubbleAddress, 100, nil, fatal)

	go func() {
		for err := range fatal {
			b.Errorf("fatal error in a goroutine: %v", err)
			cancel()
			return
		}
	}()

	testutils.WaitForServer(ctx, b.Logf, hubbleAddress)

	hubbleConn, err := grpc.DialContext(ctx, hubbleAddress, grpc.WithInsecure())
	if err != nil {
		b.Fatalf("failed to connect to Hubble server: %v", err)
	}

	defer hubbleConn.Close()

	for _, encoding := range converter.EncodingFormats() {
		process := func() {
			flows := make(chan *logsV1.ResourceLogs, logBufferSize)
			errs := make(chan error)

			go processors.FlowReciever(ctx, hubbleConn, encoding, false, flows, errs)
			for {
				select {
				case _ = <-flows: // drop
				case <-ctx.Done():
					return
				case err := <-errs:
					if testutils.IsEOF(err) {
						return
					}
					b.Fatal(err)
				}
			}
		}

		b.Run(encoding, func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				process()
			}
		})
	}
}
