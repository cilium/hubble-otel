package converter_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"github.com/sirupsen/logrus"
	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
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

func TestAllModes(t *testing.T) {
	modes := []*converter.FlowConverter{
		{
			Encoding: converter.EncodingJSON,
		},
		{
			Encoding: converter.EncodingJSONBASE64,
		},
		{
			Encoding: converter.EncodingFlatStringMap,
		},
		{
			Encoding:      converter.EncodingFlatStringMap,
			UseAttributes: true,
		},
		{
			Encoding: converter.EncodingSemiFlatTypedMap,
		},
		{
			Encoding:      converter.EncodingSemiFlatTypedMap,
			UseAttributes: true,
		},
		{
			Encoding: converter.EncodingTypedMap,
		},
		{
			Encoding:      converter.EncodingTypedMap,
			UseAttributes: true,
		},
	}

	for _, c := range modes {
		t.Run(fmt.Sprintf("c=%+v", *c), func(t *testing.T) {
			for _, flow := range getFlowSamples(t, "../testdata/basic-sample-10-flows.json") {
				logs, err := c.Convert(flow)
				if err != nil {
					t.Error(err)
				}
				if logs == nil {
					t.Error("logs shouldn't be nil")
				}
				if logs.Resource == nil {
					t.Error("resource shouldn't be nil")
				}
				if logs.Resource == nil {
					t.Error("resource shouldn't be nil")
				}
				if len(logs.Resource.Attributes) == 0 {
					t.Error("resource attributes shouldn't be empty")
				}
				hasNodeName := false
				for _, attr := range logs.Resource.Attributes {
					if attr.Key == converter.ResourceCiliumNodeName {
						hasNodeName = true
						if attr.Value.GetStringValue() != flow.GetNodeName() {
							t.Error("node name is wrong")
						}
					}
				}
				if !hasNodeName {
					t.Error("node name is not set")
				}
				if len(logs.InstrumentationLibraryLogs) != 1 {
					t.Error("exactly one log record is expected")
				}
				if len(logs.InstrumentationLibraryLogs[0].Logs) != 1 {
					t.Error("exactly one log record is expected")
				}

				logRecord := logs.InstrumentationLibraryLogs[0].Logs[0]

				var payload *commonV1.AnyValue

				hasVersionAttr := false
				hasEncodingAttr := false
				hasPayloadAttr := false
				for _, attr := range logRecord.Attributes {
					switch attr.Key {
					case converter.AttributeEventKindVersion:
						hasVersionAttr = true
						if attr.Value.GetStringValue() != converter.AttributeEventKindVersionFlowV1alpha1 {
							t.Error("version is wrong")
						}
					case converter.AttributeEventEncoding:
						hasEncodingAttr = true
						if attr.Value.GetStringValue() != c.Encoding {
							t.Error("econding is wrong")
						}
					case converter.AttributeEventPayload:
						hasPayloadAttr = true
						payload = attr.Value
					}
				}
				if !hasVersionAttr {
					t.Error("version is not set")
				}
				if !hasEncodingAttr {
					t.Error("encoding is not set")
				}

				if c.UseAttributes {
					if logRecord.Body != nil {
						t.Error("body should be unset when attributes are set")
					}
					if len(logRecord.Attributes) != 3 {
						t.Error("attributes should be set when attributes are set")
					}
					if !hasPayloadAttr {
						t.Error("payload should be set")
					}
				} else {
					if logRecord.Body == nil {
						t.Error("body cannot be nil")
					}
					payload = logRecord.Body
				}

				if payload == nil {
					t.Error("payload cannot be nil")
				}
				switch c.Encoding {
				case converter.EncodingJSON, converter.EncodingJSONBASE64:
					if payload.GetStringValue() == "" {
						t.Error("payload should be a non-empty string")
					}
				case converter.EncodingFlatStringMap, converter.EncodingSemiFlatTypedMap, converter.EncodingTypedMap:
					m := payload.GetKvlistValue()
					if m == nil {
						t.Error("payload should be a map")
					}
					if len(m.GetValues()) == 0 {
						t.Error("payload should not be empty")
					}
				default:
					t.Errorf("untested ecoding: %s", c.Encoding)
				}
			}
		})
	}
}

func getFlowSamples(t *testing.T, path string) []*observer.GetFlowsResponse {
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
