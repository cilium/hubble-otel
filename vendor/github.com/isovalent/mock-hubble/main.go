package main

import (
	"context"
	"flag"
	"os"
	"os/signal"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/hubble/server"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/logging/logfields"

	mockHubbleObeserver "github.com/isovalent/mock-hubble/observer"
)

func main() {
	address := flag.String("address", "localhost:4245", "listen on this address")
	rateAdjustment := flag.Int("rateAdjustment", 0, "flow rate adjustment, use negative number to slow down and positive to speed-up")
	dir := flag.String("dir", "./", "read flow samples from this directory")
	debug := flag.Bool("debug", false, "enable debug logs")

	flag.Parse()

	log := logrus.New()
	if *debug {
		log.SetLevel(logrus.DebugLevel)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	err := start(ctx, log, *dir, *address, *rateAdjustment)
	if err != nil {
		log.WithError(err).Error("Failed to initialize Hubble server")
		os.Exit(1)
	}
}

func start(ctx context.Context, log *logrus.Logger, dir, address string, rateAdjustment int) error {
	mockObeserver, err := mockHubbleObeserver.New(log.WithField(logfields.LogSubsys, "mock-hubble-observer"),
		mockHubbleObeserver.WithSampleDir(dir),
		mockHubbleObeserver.WithRateAdjustment(int64(rateAdjustment)),
	)
	if err != nil {
		return err
	}

	mockServer, err := server.NewServer(log.WithField(logfields.LogSubsys, "mock-hubble-server"),
		serveroption.WithTCPListener(address),
		serveroption.WithHealthService(),
		serveroption.WithObserverService(mockObeserver),
		serveroption.WithInsecure(),
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
			return nil
		}
	}

}
