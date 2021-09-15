package logconv_test

import (
	"fmt"
	"testing"

	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsV1 "go.opentelemetry.io/proto/otlp/logs/v1"

	"github.com/isovalent/hubble-otel/common"
	"github.com/isovalent/hubble-otel/logconv"
	"github.com/isovalent/hubble-otel/testutil"
)

func TestAllModes(t *testing.T) {
	modes := []*logconv.FlowConverter{
		logconv.NewFlowConverter(common.EncodingJSON, false),
		logconv.NewFlowConverter(common.EncodingJSONBASE64, false),
		logconv.NewFlowConverter(common.EncodingFlatStringMap, false),
		logconv.NewFlowConverter(common.EncodingFlatStringMap, true),
		logconv.NewFlowConverter(common.EncodingSemiFlatTypedMap, false),
		logconv.NewFlowConverter(common.EncodingSemiFlatTypedMap, true),
		logconv.NewFlowConverter(common.EncodingTypedMap, false),
		logconv.NewFlowConverter(common.EncodingTypedMap, true),
	}

	for _, c := range modes {
		t.Run(fmt.Sprintf("c=%+v", *c), func(t *testing.T) {
			for _, flow := range testutil.GetFlowSamples(t, "../testdata/basic-sample-10-flows.json") {
				logsMsg, err := c.Convert(flow)
				if err != nil {
					t.Error(err)
				}

				logs, ok := logsMsg.Interface().(*logsV1.ResourceLogs)
				if !ok {
					t.Fatal("cannot convert protoreflect.Message to *logsV1.ResourceLogs")
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
					if attr.Key == common.ResourceCiliumNodeName {
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
					case common.AttributeEventKindVersion:
						hasVersionAttr = true
						if attr.Value.GetStringValue() != common.AttributeEventKindVersionFlowV1alpha1 {
							t.Error("version is wrong")
						}
					case common.AttributeEventEncoding:
						hasEncodingAttr = true
						if attr.Value.GetStringValue() != c.Encoding {
							t.Error("econding is wrong")
						}
					case common.AttributeEventPayload:
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
					t.Errorf("untested ecoding: %s", c.Encoding)
				}
			}
		})
	}
}
