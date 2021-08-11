package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/service"
	"go.opentelemetry.io/collector/service/defaultcomponents"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/hubble/server"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/logging/logfields"
	mockHubbleObeserver "github.com/isovalent/mock-hubble/observer"
)

func TestBasicIntegrationWithTLS(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	isFalse := false
	isTrue := true
	newString := func(s string) *string { return &s }

	hubbleAddress := "localhost:4245"
	colletorAddressGRPC := "localhost:55690"

	go runOpenTelemtryCollector(ctx, t)

	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	go runMockHubble(ctx, log, "testdata/2021-06-16-sample-flows-istio-gke", hubbleAddress, 100)

	commonFlagsTLS := &flagsTLS{
		enable:               &isTrue,
		insecureSkipVerify:   &isFalse,
		clientCertificate:    newString("testdata/certs/test-client.pem"),
		clientKey:            newString("testdata/certs/test-client-key.pem"),
		certificateAuthority: newString("testdata/certs/ca.pem"),
	}

	flagsHubble := flags{
		address: &hubbleAddress,
		tls:     commonFlagsTLS,
	}

	flagsOTLP := flags{
		address: &colletorAddressGRPC,
		tls:     commonFlagsTLS,
	}

	waitForServer(t, colletorAddressGRPC)
	waitForServer(t, hubbleAddress)

	if err := run(flagsHubble, flagsOTLP, 10); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runOpenTelemtryCollector(ctx context.Context, t *testing.T) {
	factories, err := defaultcomponents.Components()
	if err != nil {
		t.Fatalf("failed to build default components: %v", err)
	}
	info := component.BuildInfo{
		Command:     "otelcol-test",
		Description: "test OpenTelemetry Collector",
		Version:     "v0.30.1",
	}

	settings := service.CollectorSettings{BuildInfo: info, Factories: factories}

	svc, err := service.New(settings)
	if err != nil {
		t.Fatalf("failed to construct the collector server: %v", err)
	}

	go func() {
		svc.Command().SetArgs([]string{
			"--config=testdata/collector-with-tls.yaml",
			"--log-level=debug",
		})
		svc.Run()
		if err := svc.Run(); err != nil {
			t.Logf("collector server run finished with error: %v", err)
		}
	}()

	<-ctx.Done()
	svc.Shutdown()
}

func runMockHubble(ctx context.Context, log *logrus.Logger, dir, address string, rateAdjustment int) error {
	mockObeserver, err := mockHubbleObeserver.New(log.WithField(logfields.LogSubsys, "mock-hubble-observer"),
		mockHubbleObeserver.WithSampleDir(dir),
		mockHubbleObeserver.WithRateAdjustment(int64(rateAdjustment)),
	)
	if err != nil {
		return err
	}

	serverConfigBuilder, err := certloader.NewWatchedServerConfig(log,
		[]string{"testdata/certs/ca.pem"},
		"testdata/certs/test-server.pem",
		"testdata/certs/test-server-key.pem",
	)
	if err != nil {
		return err
	}

	mockServer, err := server.NewServer(log.WithField(logfields.LogSubsys, "mock-hubble-server"),
		serveroption.WithTCPListener(address),
		serveroption.WithServerTLS(serverConfigBuilder),
		serveroption.WithHealthService(),
		serveroption.WithObserverService(mockObeserver),
	)
	if err != nil {
		return err
	}

	log.WithField("address", address).Info("Starting Hubble server")

	if err := mockServer.Serve(); err != nil {
		return err
	}

	errs := make(chan error)
	defer close(errs)

	for {
		select {
		case err = <-errs:
			return err
		case <-ctx.Done():
			log.WithField("address", address).Info("Stopping Hubble server")
			mockServer.Stop()
			mockObeserver.Stop()
			return nil
		}
	}

}

func waitForServer(t *testing.T, address string) {
	for {
		_, err := net.Dial("tcp", address)
		if err == nil {
			break
		}
		t.Logf("waiting for collector to listend on %q (err: %v)", address, err)
		time.Sleep(250 * time.Millisecond)
	}
}
