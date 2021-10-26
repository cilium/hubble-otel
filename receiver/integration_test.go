package receiver_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/isovalent/hubble-otel/receiver"
	"github.com/isovalent/hubble-otel/testutil"
)

const (
	hubbleAddress       = "localhost:4245"
	promReceiverAddress = "localhost:8888"
	promExporterAddress = "localhost:8889"

	metricsURL = "http://" + promExporterAddress + "/metrics"
)

func TestIntegration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fatal := make(chan error, 1)

	log := logrus.New()
	//log.SetLevel(logrus.DebugLevel)

	tlsPaths := &testutil.TLSPaths{
		Certificate:          "../testdata/certs/test-server.pem",
		Key:                  "../testdata/certs/test-server-key.pem",
		CertificateAuthority: "../testdata/certs/ca.pem",
	}

	go testutil.RunMockHubble(context.Background(), log, "../testdata/2021-10-04-sample-flows-istio-gke-l7", hubbleAddress, 100, tlsPaths, fatal)

	testutil.WaitForServer(ctx, t.Logf, hubbleAddress)

	go testutil.RunOpenTelemtryCollector(ctx, t, "testdata/collector-with-tls.yaml", fatal, receiver.NewFactory())

	go func() {
		for err := range fatal {
			fmt.Printf("fatal error in a goroutine: %v\n", err)
			cancel()
			return
		}
	}()

	testutil.WaitForServer(ctx, t.Logf, promExporterAddress)
	testutil.WaitForServer(ctx, t.Logf, promReceiverAddress)
}
