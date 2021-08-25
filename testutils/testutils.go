package testutils

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/service"
	"go.opentelemetry.io/collector/service/defaultcomponents"
	"google.golang.org/grpc/status"

	promdto "github.com/prometheus/client_model/go"
	promexpfmt "github.com/prometheus/common/expfmt"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/hubble/server"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/logging/logfields"
	mockHubbleObeserver "github.com/isovalent/mock-hubble/observer"
)

const (
	pollingTimeout = 2 * time.Minute
	waitPeriod     = 250 * time.Millisecond
)

type TLSPaths struct {
	Certificate, Key, CertificateAuthority string
}

func RunMockHubble(ctx context.Context, log *logrus.Logger, dir, address string, rateAdjustment int, withTLSPath *TLSPaths, fatal chan<- error) {
	mockObeserver, err := mockHubbleObeserver.New(log.WithField(logfields.LogSubsys, "mock-hubble-observer"),
		mockHubbleObeserver.WithSampleDir(dir),
		mockHubbleObeserver.WithRateAdjustment(int64(rateAdjustment)),
	)
	if err != nil {
		fatal <- err
		return
	}

	tlsOption := serveroption.WithInsecure()

	if withTLSPath != nil {
		serverConfigBuilder, err := certloader.NewWatchedServerConfig(log,
			[]string{withTLSPath.CertificateAuthority},
			withTLSPath.Certificate,
			withTLSPath.Key,
		)
		if err != nil {
			fatal <- err
			return
		}
		tlsOption = serveroption.WithServerTLS(serverConfigBuilder)
	}

	mockServer, err := server.NewServer(log.WithField(logfields.LogSubsys, "mock-hubble-server"),
		serveroption.WithTCPListener(address),
		tlsOption,
		serveroption.WithHealthService(),
		serveroption.WithObserverService(mockObeserver),
	)
	if err != nil {
		fatal <- err
		return
	}

	log.WithField("address", address).Info("Starting Hubble server")

	if err := mockServer.Serve(); err != nil {
		fatal <- err
		return
	}

	for {
		select {
		case <-ctx.Done():
			log.WithField("address", address).Info("Stopping Hubble server")
			mockServer.Stop()
			mockObeserver.Stop()
			return
		}
	}

}

func RunOpenTelemtryCollector(ctx context.Context, t *testing.T, configPath, logLevel string, fatal chan<- error) {
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
		fatal <- fmt.Errorf("failed to construct the collector server: %v", err)
		return
	}

	go func() {
		svc.Command().SetArgs([]string{
			"--config=" + configPath,
			"--log-level=" + logLevel,
		})

		if err = svc.Run(); err != nil {
			fatal <- fmt.Errorf("collector server run finished with error: %v", err)
			return
		} else {
			t.Log("collector server run finished without errors")
		}
	}()

	<-ctx.Done()
	svc.Shutdown()
}

func WaitForServer(ctx context.Context, t *testing.T, address string) {
	ctx, cancel := context.WithTimeout(ctx, pollingTimeout)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, err := net.Dial("tcp", address)
			if conn != nil {
				if err := conn.Close(); err != nil {
					t.Logf("ignoring connection closure error: %v", err)
				}
			}
			if err == nil {
				t.Logf("server is now listening on %q", address)
				return
			}
			t.Logf("waiting for server to listen on %q (err: %v)", address, err)
			time.Sleep(waitPeriod)
		}
	}
}

func GetMetricFamilies(ctx context.Context, t *testing.T, url string) map[string]*promdto.MetricFamily {
	ctx, cancel := context.WithTimeout(ctx, pollingTimeout)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			resp, err := http.Get(url)
			if err != nil {
				t.Fatalf("failed to get prometheus metrics: %v", err)
				return nil
			}

			mf, err := (&promexpfmt.TextParser{}).TextToMetricFamilies(resp.Body)
			if err != nil {
				t.Fatalf("failed to parse prometheus metrics: %v", err)
				return nil
			}
			if up, ok := mf["up"]; ok && len(up.GetMetric()) > 0 {
				return mf
			}
			t.Logf("waiting for prom metrics to become available")
			time.Sleep(waitPeriod)
		}
	}
}

func IsEOF(err error) bool {
	s, ok := status.FromError(err)
	return ok && s.Proto().GetMessage() == "EOF"
}
