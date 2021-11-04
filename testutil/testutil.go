package testutil

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/prometheusexporter"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusreceiver"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/service"
	"go.opentelemetry.io/collector/service/defaultcomponents"

	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	resourceV1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc/status"

	promdto "github.com/prometheus/client_model/go"
	promexpfmt "github.com/prometheus/common/expfmt"

	flowV1 "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	mockHubbleObeserver "github.com/cilium/mock-hubble/observer"

	"github.com/cilium/hubble-otel/common"
)

const (
	pollingTimeout = 2 * time.Minute
	waitPeriod     = 250 * time.Millisecond
)

type TLSPaths = mockHubbleObeserver.TLSPaths

var RunMockHubble = mockHubbleObeserver.Run

func GetFlowSamples(t *testing.T, path string) []*observer.GetFlowsResponse {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	samples := []*observer.GetFlowsResponse{}

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		f := &flowV1.Flow{}
		var obj struct {
			Flow *flowV1.Flow `json:"flow"`
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

func RunOpenTelemtryCollector(ctx context.Context, t *testing.T, configPath string, fatal chan<- error, extraReceiverFactories ...component.ReceiverFactory) {
	t.Helper()

	factories, err := defaultcomponents.Components()
	if err != nil {
		t.Fatalf("failed to build default components: %v", err)
	}

	additionalReceiverFactories := []component.ReceiverFactory{
		prometheusreceiver.NewFactory(),
	}
	additionalReceiverFactories = append(additionalReceiverFactories, extraReceiverFactories...)

	additionalReceivers, err := component.MakeReceiverFactoryMap(
		additionalReceiverFactories...,
	)
	if err != nil {
		t.Fatalf("failed to build additional receivers: %v", err)
	}
	for k, v := range additionalReceivers {
		factories.Receivers[k] = v
	}

	additionalExporters, err := component.MakeExporterFactoryMap(
		prometheusexporter.NewFactory(),
	)
	if err != nil {
		t.Fatalf("failed to build additional exporters: %v", err)
	}
	for k, v := range additionalExporters {
		factories.Exporters[k] = v
	}

	info := component.BuildInfo{
		Command:     "otelcol-test",
		Description: "test OpenTelemetry Collector",
		Version:     "v0.30.1",
	}

	settings := service.CollectorSettings{BuildInfo: info, Factories: factories}

	cmd := service.NewCommand(settings)
	cmd.SetArgs([]string{
		"--config=" + configPath,
	})

	go func() {
		err := cmd.ExecuteContext(ctx)
		if err != nil {
			fatal <- fmt.Errorf("collector server run finished with error: %v", err)
			return
		} else {
			t.Log("collector server run finished without errors")
		}
	}()

	<-ctx.Done()
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

func CheckCounterMetricIsZero(t *testing.T, families map[string]*promdto.MetricFamily, metrics ...string) {
	t.Helper()

	for _, k := range metrics {
		m, ok := families[k]
		if !ok || len(m.GetMetric()) == 0 {
			t.Errorf("metric %q should be present", k)
			continue
		}
		if v := m.GetMetric()[0].Counter.Value; *v != 0.0 {
			t.Errorf("metric %q should be zero", k)
		}
	}
}

func CheckCounterMetricIsGreaterThen(t *testing.T, value float64, families map[string]*promdto.MetricFamily, metrics ...string) {
	t.Helper()

	for _, k := range metrics {
		m, ok := families[k]
		if !ok || len(m.GetMetric()) == 0 {
			t.Errorf("metric %q should be present", k)
			continue
		}
		if v := m.GetMetric()[0].Counter.Value; *v < value {
			t.Errorf("metric %q should be at least %f, not %f", k, value, *v)
		}
	}
}

func IsEOF(err error) bool {
	s, ok := status.FromError(errors.Unwrap(err))
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

	var (
		hasNodeName,
		shouldHaveNamespaceName, hasNamespaceName,
		shouldHavePodName, hasPodName,
		_ bool
	)
	if src := hubbleResp.GetFlow().Source; src != nil {
		shouldHaveNamespaceName = src.Namespace != ""
		shouldHavePodName = src.PodName != ""
	}
	for _, attr := range res.Attributes {
		switch attr.Key {
		case common.OTelAttrK8sNodeName:
			hasNodeName = true
			if attr.Value.GetStringValue() != hubbleResp.GetNodeName() {
				t.Error("node name is wrong")
			}
		case common.OTelAttrK8sNamespaceName:
			hasNamespaceName = true
		case common.OTelAttrK8sPodName:
			hasPodName = true
		}
	}
	if !hasNodeName {
		t.Error("node name is not set")
	}
	if shouldHaveNamespaceName && !hasNamespaceName {
		t.Error("namespace name is not set")
	}
	if shouldHavePodName && !hasPodName {
		t.Error("pod name is not set")
	}
}

func CheckAttributes(t *testing.T, attrs []*commonV1.KeyValue, encodingOptions common.EncodingOptions) *commonV1.AnyValue {
	t.Helper()

	var payload *commonV1.AnyValue

	hasVersionAttr := false
	hasEncodingAttr := false
	hasEncodingOptionsAttr := false
	hasPayloadInTopLevelKeys := false

	for _, attr := range attrs {
		switch attr.Key {
		case common.AttributeEventKindVersion:
			hasVersionAttr = true
			if attr.Value.GetStringValue() != common.AttributeEventKindVersionFlowV1alpha1 {
				t.Error("version is wrong")
			}
		case common.AttributeEventEncoding:
			hasEncodingAttr = true
			if attr.Value.GetStringValue() != encodingOptions.EncodingFormat() {
				t.Error("econding is wrong")
			}
		case common.AttributeEventEncodingOptions:
			hasEncodingOptionsAttr = true
			if attr.Value.GetStringValue() != encodingOptions.String() {
				t.Error("econding options are wrong")
			}
		case common.AttributeEventObject:
			payload = attr.Value
		}
		if strings.HasPrefix(attr.Key, common.AttributeFlowEventNamespace) {
			if payload == nil {
				payload = &commonV1.AnyValue{
					Value: &commonV1.AnyValue_KvlistValue{
						KvlistValue: &commonV1.KeyValueList{},
					},
				}
			}
			payload.GetKvlistValue().Values = append(payload.GetKvlistValue().Values, attr)
			hasPayloadInTopLevelKeys = true
		}
	}

	if !hasVersionAttr {
		t.Error("version is not set")
	}
	if !hasEncodingAttr {
		t.Error("encoding is not set")
	}
	if !hasEncodingOptionsAttr {
		t.Error("encoding options are not set")
	}

	expectedMinLen := 3
	expectedMaxLen := 4

	if payload != nil {
		expectedMinLen += 1
		expectedMaxLen += 1
	}
	if encodingOptions.WithTopLevelKeys() && !encodingOptions.WithLogPayloadAsBody() {
		if !hasPayloadInTopLevelKeys {
			t.Fatal("missing payload keys")
		}
		extraKeys := len(payload.GetKvlistValue().Values)
		expectedMinLen = 3 + extraKeys
		expectedMaxLen = 4 + extraKeys
	}
	ciliumAttrs := 0
	for _, attr := range attrs {
		if strings.HasPrefix(attr.Key, "cilium.") {
			ciliumAttrs++
		}
	}
	if ciliumAttrs < expectedMinLen || ciliumAttrs > expectedMaxLen {
		t.Errorf("should have between %d and %d attributes in \"cilium.\" namespace, but found %d", expectedMinLen, expectedMaxLen, ciliumAttrs)
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

func BoolValueRefs() (*bool, *bool) {
	_false, _true := false, true
	return &_false, &_true
}
