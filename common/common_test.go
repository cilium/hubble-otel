package common_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/reflect/protoreflect"

	flowV1 "github.com/cilium/cilium/api/v1/flow"

	"github.com/isovalent/hubble-otel/common"
	"github.com/isovalent/hubble-otel/logconv"
	"github.com/isovalent/hubble-otel/receiver"
	"github.com/isovalent/hubble-otel/testutil"
)

const (
	hubbleAddress = "localhost:4245"
	logBufferSize = 2048
)

var _false, _true = testutil.BoolValueRefs()

func BenchmarkAllModes(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fatal := make(chan error, 1)

	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	go testutil.RunMockHubble(ctx, log, "../testdata/2021-10-04-sample-flows-istio-gke-l7", hubbleAddress, 100, nil, fatal)

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
	encodingOptions := []*common.EncodingOptions{
		// LogPayloadAsBody is irrelevant for benchmarking, test all remaining combinations
		{TopLevelKeys: _true, LabelsAsMaps: _true, HeadersAsMaps: _false},
		{TopLevelKeys: _true, LabelsAsMaps: _false, HeadersAsMaps: _false},
		{TopLevelKeys: _false, LabelsAsMaps: _true, HeadersAsMaps: _false},
		{TopLevelKeys: _false, LabelsAsMaps: _false, HeadersAsMaps: _false},
		{TopLevelKeys: _true, LabelsAsMaps: _true, HeadersAsMaps: _true},
		{TopLevelKeys: _true, LabelsAsMaps: _false, HeadersAsMaps: _true},
		{TopLevelKeys: _false, LabelsAsMaps: _true, HeadersAsMaps: _true},
		{TopLevelKeys: _false, LabelsAsMaps: _false, HeadersAsMaps: _true},
	}

	for e := range encodingFormats {
		for o := range encodingOptions {
			options := encodingOptions[o]
			options.Encoding = &encodingFormats[e]

			process := func() {
				flows := make(chan protoreflect.Message, logBufferSize)
				errs := make(chan error)

				go receiver.Run(ctx, hubbleConn, logconv.NewFlowConverter(log, options), flows, errs)
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

			b.Run(options.EncodingFormat()+":"+options.String(), func(b *testing.B) {
				for n := 0; n < b.N; n++ {
					process()
				}
			})
		}
	}
}

func TestRoudtripEncoding(t *testing.T) {
	log := logrus.New()
	//log.SetLevel(logrus.DebugLevel)

	encodingFormats := []string{
		common.EncodingJSON,
		common.EncodingTypedMap,
	}

	encodingOptions := []*common.EncodingOptions{
		{TopLevelKeys: _false, LabelsAsMaps: _false, HeadersAsMaps: _false, LogPayloadAsBody: _false},
	}

	samples := []string{
		"basic-sample-10-flows.json",
		"basic-sample-330-dns-flows.json",
		"basic-sample-348-http-flows.json",
	}

	for s := range samples {
		for e := range encodingFormats {
			for o := range encodingOptions {
				sample := samples[s]
				options := encodingOptions[o]
				options.Encoding = &encodingFormats[e]

				c := &common.FlowEncoder{
					EncodingOptions: options,
					Logger:          log,
				}

				t.Run("("+sample+")/"+options.EncodingFormat()+":"+options.String(), func(t *testing.T) {
					for _, f := range testutil.GetFlowSamples(t, "../testdata/"+sample) {
						v, err := c.ToValue(f)
						if err != nil {
							t.Error(err)
						}
						if v == nil {
							t.Error("value cannot be nil")
						}

						result := []byte{}

						source, err := common.MarshalJSON(f.GetFlow())
						if err != nil {
							t.Error(err)
						}
						switch options.EncodingFormat() {
						case common.EncodingTypedMap:
							result = roundTripJSON(t, v)
						case common.EncodingJSON:
							result = []byte(v.GetStringValue())
						}

						sourceData := string(source)
						if len(sourceData) == 0 {
							t.Errorf("encoded source cannot be empty")
						}
						resultData := string(result)
						if len(resultData) == 0 {
							t.Errorf("encoded result cannot be empty")
						}

						require.JSONEq(t, sourceData, resultData)
						// t.Logf("source = %s", sourceData)
						// t.Logf("result = %s", resultData)
					}
				})
			}
		}
	}
}

func TestNonRoudtripEncoding(t *testing.T) {
	log := logrus.New()
	//log.SetLevel(logrus.DebugLevel)

	modes := map[string][]*common.EncodingOptions{
		// test option combinations that relevant to particular encoding
		common.EncodingSemiFlatTypedMap: {
			{TopLevelKeys: _false, LabelsAsMaps: _false, HeadersAsMaps: _false, LogPayloadAsBody: _false},
			{TopLevelKeys: _true, LabelsAsMaps: _true, HeadersAsMaps: _true, LogPayloadAsBody: _false},
		},

		common.EncodingFlatStringMap: {
			{TopLevelKeys: _false, LabelsAsMaps: _false, HeadersAsMaps: _false, LogPayloadAsBody: _false},
			{TopLevelKeys: _true, LabelsAsMaps: _true, HeadersAsMaps: _true, LogPayloadAsBody: _false},
		},
		common.EncodingTypedMap: {
			// this test only touches on conversion for labels and headers,
			// general functionality of TypedMap is covered by TestRoudtripEncoding
			{TopLevelKeys: _false, LabelsAsMaps: _true, HeadersAsMaps: _true, LogPayloadAsBody: _false},
		},
	}

	samples := map[string]func(*testing.T, *common.EncodingOptions, map[string]interface{}){
		"basic-sample-5-http-flows.json": checkFlatEncodingForHTTPFlows,
		"basic-sample-5-dns-flows.json":  checkFlatEncodingForDNSFlows,
	}

	for samplePath := range samples {
		for k := range modes {
			for i := range modes[k] {
				options := modes[k][i]
				options.Encoding = &k
				sampleCheck := samples[samplePath]

				c := &common.FlowEncoder{
					EncodingOptions: options,
					Logger:          log,
				}

				t.Run("("+samplePath+")/"+options.EncodingFormat()+":"+options.String(), func(t *testing.T) {
					for _, f := range testutil.GetFlowSamples(t, "../testdata/"+samplePath) {
						v, err := c.ToValue(f)
						if err != nil {
							t.Error(err)
						}
						if v == nil {
							t.Error("value cannot be nil")
						}

						result := toRaw(v.GetValue()).(map[string]interface{})

						sampleCheck(t, options, result)
					}
				})
			}
		}
	}
}

func checkLabels(t *testing.T, key string, labels interface{}, asMap bool) {
	t.Helper()

	if asMap {
		if labels, ok := labels.(map[string]interface{}); ok {
			for k, v := range labels {
				if _, ok := v.(string); !ok {
					t.Errorf("label value for %q is %T, should be a strings", k, v)
				}
			}
		} else {
			t.Errorf("value of %q is %T, should be a map", key, labels)
		}
	} else {
		if labels, ok := labels.([]interface{}); ok {
			for _, v := range labels {
				if _, ok := v.(string); !ok {
					t.Errorf("label value is %T, should be a strings", v)
				}
			}
		} else {
			t.Errorf("value of %q is %T, should be a list", key, labels)
		}
	}
}

func checkFlatEncodingCommon(t *testing.T, encodingOptions *common.EncodingOptions, result map[string]interface{}) {
	t.Helper()

	format := encodingOptions.EncodingFormat()

	if format == common.EncodingTypedMap {
		if source, ok := result["source"]; ok {
			if labels, ok := source.(map[string]interface{})["labels"]; ok {
				checkLabels(t, "source.labels", labels, true)
			} else {
				t.Errorf("missing key %q", "source.labels")
			}
		} else {
			t.Errorf("missing key %q", "source")
		}
		if destination, ok := result["destination"]; ok {
			if labels, ok := destination.(map[string]interface{})["labels"]; ok {
				checkLabels(t, "destination.labels", labels, true)
			}
		}

		return
	}

	if l, e := len(result), 25; l < e {
		t.Errorf("resulting object doesn't meat minimum lenght test (have: %d, expected %d)", l, e)
	}

	keys := []string{
		"IP.ipVersion",
		"IP.source",
		"Type",
		"Summary",
		"destination.identity",
		"source.identity",
		"source.namespace",
		"source.pod_name",
		"time",
		"traffic_direction",
		"verdict",
		"l4.TCP.source_port",
		"l4.TCP.destination_port",
		"l7.type",
	}

	if format == common.EncodingSemiFlatTypedMap {
		keys = append(keys,
			"source.labels",
		)
	}

	for _, k := range keys {
		k = resolveKey(k, encodingOptions)
		if _, ok := result[k]; !ok {
			t.Errorf("missing required key %q", k)
		}
	}

	if format == common.EncodingSemiFlatTypedMap {
		sk := resolveKey("source.labels", encodingOptions)
		if labels, ok := result[sk]; ok {
			checkLabels(t, sk, labels, encodingOptions.WithLabelsAsMaps())
		} else {
			t.Errorf("missing required key %q", "source.labels")
		}
		dk := resolveKey("destination.labels", encodingOptions)
		if labels, ok := result[dk]; ok {
			checkLabels(t, dk, labels, encodingOptions.WithLabelsAsMaps())
		}
	}
}

func resolveKey(k string, encodingOptions *common.EncodingOptions) string {
	if encodingOptions.WithTopLevelKeys() {
		return common.AttributeFlowEventNamespace + "." + k
	}
	return k
}

func checkFlatEncodingForHTTPFlows(t *testing.T, encodingOptions *common.EncodingOptions, result map[string]interface{}) {
	t.Helper()

	checkFlatEncodingCommon(t, encodingOptions, result)

	format := encodingOptions.EncodingFormat()

	if format == common.EncodingTypedMap {
		if l7, ok := result["l7"]; ok {
			if http, ok := l7.(map[string]interface{})["http"]; ok {
				if headers, ok := http.(map[string]interface{})["headers"]; ok {
					if encodingOptions.WithHeadersAsMaps() {
						if _, ok := headers.(map[string]interface{}); !ok {
							t.Errorf("headers should be a map, not a %T", headers)
						}
					} else {
						if _, ok := headers.([]interface{}); !ok {
							t.Errorf("headers should be a list, not a %T", headers)
						}
					}
				} else {
					t.Errorf("missing key %q", "l7.http.headers")
				}
			} else {
				t.Errorf("missing key %q", "l7.http")
			}
		} else {
			t.Errorf("missing key %q", "l7")
		}

		return
	}

	keys := []string{
		"l7.http.protocol",
		"l7.http.method",
		"l7.http.url",
	}

	for _, k := range keys {
		k = resolveKey(k, encodingOptions)
		if _, ok := result[k]; !ok {
			t.Errorf("missing required key %q", k)
		}
	}

	isResponse := false

	if code, ok := result[resolveKey("l7.http.code", encodingOptions)]; ok {
		isResponse = true
		switch format {
		case common.EncodingSemiFlatTypedMap:
			if _, ok := code.(int64); !ok {
				t.Errorf("HTTP code is a %T, should be a int64", code)
			}
		case common.EncodingFlatStringMap:
			if _, ok := code.(string); !ok {
				t.Errorf("HTTP code is a %T, should be a string", code)
			}
		}
	}

	if encodingOptions.WithHeadersAsMaps() {
		if isResponse {
			if accept, ok := result[resolveKey("l7.http.headers.accept", encodingOptions)]; ok {
				if _, ok := accept.([]interface{}); !ok {
					t.Errorf("header value is %T, should be a list", accept)
				}
			} else {
				t.Errorf("accept header missing")
			}
		} else {
			if userAgent, ok := result[resolveKey("l7.http.headers.user_agent", encodingOptions)]; ok {
				if _, ok := userAgent.([]interface{}); !ok {
					t.Errorf("header value is %T, should be a list", userAgent)
				}
			} else {
				t.Errorf("user_agent header missing")
			}
		}
	}
}

func checkFlatEncodingForDNSFlows(t *testing.T, encodingOptions *common.EncodingOptions, result map[string]interface{}) {
	t.Helper()

	checkFlatEncodingCommon(t, encodingOptions, result)

	format := encodingOptions.EncodingFormat()

	if format == common.EncodingTypedMap {
		// there nothing specific to this encoding when it comes to DNS flows
		return
	}

	t.Logf("result = %#v", result)

	keys := []string{
		"l7.dns.observation_source",
		"l7.dns.query",
	}

	switch format {
	case common.EncodingSemiFlatTypedMap:
		keys = append(keys, "l7.dns.qtypes")
	case common.EncodingFlatStringMap:
		keys = append(keys, "l7.dns.qtypes.0")
	}

	for _, k := range keys {
		k = resolveKey(k, encodingOptions)
		if _, ok := result[k]; !ok {
			t.Errorf("missing required key %q", k)
		}
	}
}

func toRaw(v interface{}) interface{} {
	switch v.(type) {
	case *commonV1.AnyValue_StringValue:
		return v.(*commonV1.AnyValue_StringValue).StringValue
	case *commonV1.AnyValue_IntValue:
		return v.(*commonV1.AnyValue_IntValue).IntValue
	case *commonV1.AnyValue_DoubleValue:
		return v.(*commonV1.AnyValue_DoubleValue).DoubleValue
	case *commonV1.AnyValue_BoolValue:
		return v.(*commonV1.AnyValue_BoolValue).BoolValue
	case *commonV1.AnyValue_BytesValue:
		return v.(*commonV1.AnyValue_BytesValue).BytesValue
	case *commonV1.AnyValue_KvlistValue:
		return keyValueListToRaw(v.(*commonV1.AnyValue_KvlistValue).KvlistValue)
	case *commonV1.AnyValue_ArrayValue:
		return arrayValueToRaw(v.(*commonV1.AnyValue_ArrayValue).ArrayValue)
	default:
		panic("unhandled type")
	}
}

func keyValueListToRaw(m *commonV1.KeyValueList) map[string]interface{} {
	raw := make(map[string]interface{})
	for _, entry := range m.Values {
		if entry == nil {
			panic(fmt.Sprintf("nil entry in %#v", m.Values))
		}
		raw[entry.Key] = toRaw(entry.Value.GetValue())
	}
	return raw
}

func arrayValueToRaw(l *commonV1.ArrayValue) []interface{} {
	raw := make([]interface{}, len(l.Values))
	for index, entry := range l.Values {
		if entry == nil {
			panic(fmt.Sprintf("nil entry in %#v", l.Values))
		}
		raw[index] = toRaw(entry.GetValue())
	}
	return raw
}

func roundTripJSON(t *testing.T, v *commonV1.AnyValue) []byte {
	t.Helper()

	// turn commonV1.AnyValue into interface{},
	// and ecode as JSON using standard codec
	data, err := json.Marshal(toRaw(v.GetValue()))
	if err != nil {
		t.Error(err)
	}
	// decode JSON into a flow.Flow
	f := &flowV1.Flow{}
	if err = json.Unmarshal(data, f); err != nil {
		t.Error(err)
	}
	// re-encode using funky protobuf encoder that
	// turns int64 & unint64 into strings and has
	// other peculiar features...
	result, err := common.MarshalJSON(f)
	if err != nil {
		t.Error(err)
	}
	return result
}
