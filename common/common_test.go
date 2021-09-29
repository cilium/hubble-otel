package common_test

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/isovalent/hubble-otel/common"
	"github.com/isovalent/hubble-otel/logconv"
	"github.com/isovalent/hubble-otel/receiver"
	"github.com/isovalent/hubble-otel/testutil"
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

	go testutil.RunMockHubble(ctx, log, "../testdata/2021-06-16-sample-flows-istio-gke", hubbleAddress, 100, nil, fatal)

	go func() {
		for err := range fatal {
			b.Errorf("fatal error in a goroutine: %v", err)
			cancel()
			return
		}
	}()

	testutil.WaitForServer(ctx, b.Logf, hubbleAddress)

	hubbleConn, err := grpc.DialContext(ctx, hubbleAddress, grpc.WithInsecure())
	if err != nil {
		b.Fatalf("failed to connect to Hubble server: %v", err)
	}

	defer hubbleConn.Close()

	encodingFormats := common.EncodingFormatsForLogs()
	encodingOptions := []common.EncodingOptions{
		// LogPayloadAsBody is irrelevant for benchmarking, test all remaining combinations
		{TopLevelKeys: true, LabelsAsMaps: true},
		{TopLevelKeys: true, LabelsAsMaps: false},
		{TopLevelKeys: false, LabelsAsMaps: true},
		{TopLevelKeys: false, LabelsAsMaps: false},
	}

	for e := range encodingFormats {
		for o := range encodingOptions {
			options := encodingOptions[o]
			options.Encoding = encodingFormats[e]

			process := func() {
				flows := make(chan protoreflect.Message, logBufferSize)
				errs := make(chan error)

				go receiver.Run(ctx, hubbleConn, logconv.NewFlowConverter(options), flows, errs)
				for {
					select {
					case _ = <-flows: // drop
					case <-ctx.Done():
						return
					case err := <-errs:
						if testutil.IsEOF(err) {
							return
						}
						b.Fatal(err)
					}
				}
			}

			b.Run(options.Encoding+":"+options.String(), func(b *testing.B) {
				for n := 0; n < b.N; n++ {
					process()
				}
			})
		}
	}
}
