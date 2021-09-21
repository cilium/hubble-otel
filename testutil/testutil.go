package testutil

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/service"
	"go.opentelemetry.io/collector/service/defaultcomponents"
	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	resourceV1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc/status"

	promdto "github.com/prometheus/client_model/go"
	promexpfmt "github.com/prometheus/common/expfmt"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/hubble/server"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/logging/logfields"
	mockHubbleObeserver "github.com/isovalent/mock-hubble/observer"

	"github.com/isovalent/hubble-otel/common"
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

func GetFlowSamples(t *testing.T, path string) []*observer.GetFlowsResponse {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	samples := []*observer.GetFlowsResponse{}

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		f := &flow.Flow{}
		var obj struct {
			Flow *flow.Flow `json:"flow"`
		}
		obj.Flow = f
		if err := json.Unmarshal(scanner.Bytes(), &obj); err == nil {
			if f == nil {
				continue
			}

			samples = append(samples, &observer.GetFlowsResponse{
				NodeName: f.GetNodeName(),
				Time:     f.GetTime(),
				ResponseTypes: &observer.GetFlowsResponse_Flow{
					Flow: f,
				},
			})
		} else {
			t.Fatal(err)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return samples
}

func RunOpenTelemtryCollector(ctx context.Context, t *testing.T, configPath, logLevel string, fatal chan<- error) {
	t.Helper()

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

func WaitForServer(ctx context.Context, logf func(format string, args ...interface{}), address string) {
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
					logf("ignoring connection closure error: %v", err)
				}
			}
			if err == nil {
				logf("server is now listening on %q", address)
				return
			}
			logf("waiting for server to listen on %q (err: %v)", address, err)
			time.Sleep(waitPeriod)
		}
	}
}

func GetMetricFamilies(ctx context.Context, t *testing.T, url string) map[string]*promdto.MetricFamily {
	t.Helper()

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

func CheckResource(t *testing.T, res *resourceV1.Resource, hubbleResp *observer.GetFlowsResponse) {
	t.Helper()

	if res == nil {
		t.Error("resource shouldn't be nil")
	}
	if len(res.Attributes) == 0 {
		t.Error("resource attributes shouldn't be empty")
	}
	hasNodeName := false
	for _, attr := range res.Attributes {
		if attr.Key == common.ResourceCiliumNodeName {
			hasNodeName = true
			if attr.Value.GetStringValue() != hubbleResp.GetNodeName() {
				t.Error("node name is wrong")
			}
		}
	}
	if !hasNodeName {
		t.Error("node name is not set")
	}
}

func CheckAttributes(t *testing.T, attrs []*commonV1.KeyValue, encoding string) *commonV1.AnyValue {
	t.Helper()

	var payload *commonV1.AnyValue

	hasVersionAttr := false
	hasEncodingAttr := false

	expectedLen := 2

	for _, attr := range attrs {
		switch attr.Key {
		case common.AttributeEventKindVersion:
			hasVersionAttr = true
			if attr.Value.GetStringValue() != common.AttributeEventKindVersionFlowV1alpha1 {
				t.Error("version is wrong")
			}
		case common.AttributeEventEncoding:
			hasEncodingAttr = true
			if attr.Value.GetStringValue() != encoding {
				t.Error("econding is wrong")
			}
		case common.AttributeEventPayload:
			payload = attr.Value
		}
	}

	if !hasVersionAttr {
		t.Error("version is not set")
	}
	if !hasEncodingAttr {
		t.Error("encoding is not set")
	}

	if payload != nil {
		expectedLen = 3
	}
	if len(attrs) != expectedLen {
		t.Errorf("should have %d attributes", expectedLen)
	}

	return payload
}

func CheckPayload(t *testing.T, payload *commonV1.AnyValue, encoding string) {
	t.Helper()

	if payload == nil {
		t.Error("payload should be set")
	}

	switch encoding {
	case common.EncodingJSON, common.EncodingJSONBASE64:
		if payload.GetStringValue() == "" {
			t.Error("payload should be a non-empty string")
		}
	case common.EncodingFlatStringMap, common.EncodingSemiFlatTypedMap, common.EncodingTypedMap:
		m := payload.GetKvlistValue()
		if m == nil {
			t.Error("payload should be a map")
		}
		if len(m.GetValues()) == 0 {
			t.Error("payload should not be empty")
		}
	default:
		t.Errorf("untested ecoding: %s", encoding)
	}
}
