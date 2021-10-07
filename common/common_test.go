package common_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/cilium/cilium/api/v1/flow"
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

	_false := new(bool)
	*_false = false
	_true := new(bool)
	*_true = true

	encodingFormats := common.EncodingFormatsForLogs()
	encodingOptions := []*common.EncodingOptions{
		// LogPayloadAsBody is irrelevant for benchmarking, test all remaining combinations
		{TopLevelKeys: _true, LabelsAsMaps: _true},
		{TopLevelKeys: _true, LabelsAsMaps: _false},
		{TopLevelKeys: _false, LabelsAsMaps: _true},
		{TopLevelKeys: _false, LabelsAsMaps: _false},
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

	_false := new(bool)
	*_false = false

	encodingOptions := []*common.EncodingOptions{
		{TopLevelKeys: _false, LabelsAsMaps: _false, LogPayloadAsBody: _false},
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
							// turn commonV1.AnyValue into interface{},
							// and ecode as JSON using standard codec
							data, err := json.Marshal(toRaw(v.GetValue()))
							if err != nil {
								t.Error(err)
							}
							// decode JSON into a flow.Flow
							f := &flow.Flow{}
							if err = json.Unmarshal(data, f); err != nil {
								t.Error(err)
							}
							// re-encode using funky protobuf encoder that
							// turns int64 & unint64 into strings and has
							// other peculiar features...
							result, err = common.MarshalJSON(f)
							if err != nil {
								t.Error(err)
							}
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
		return nil
	}
}

func keyValueListToRaw(m *commonV1.KeyValueList) map[string]interface{} {
	raw := make(map[string]interface{})
	for _, entry := range m.Values {
		raw[entry.Key] = toRaw(entry.Value.GetValue())
	}
	return raw
}

func arrayValueToRaw(l *commonV1.ArrayValue) []interface{} {
	raw := make([]interface{}, len(l.Values))
	for index, entry := range l.Values {
		raw[index] = toRaw(entry.GetValue())
	}
	return raw
}
