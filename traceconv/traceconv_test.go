package traceconv_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	traceV1 "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/isovalent/hubble-otel/common"
	"github.com/isovalent/hubble-otel/testutil"
	"github.com/isovalent/hubble-otel/traceconv"
)

func TestAllModes(t *testing.T) {

	newFlowConverter := func(m string) *traceconv.FlowConverter {
		spanDB, err := os.MkdirTemp("", "hubble-otel-test-trace-cache-")
		if err != nil {
			t.Fatal(err)
		}
		c, err := traceconv.NewFlowConverter(m, spanDB)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	modes := []string{
		common.EncodingJSON,
		common.EncodingJSONBASE64,
		common.EncodingFlatStringMap,
		common.EncodingFlatStringMap,
		common.EncodingSemiFlatTypedMap,
		common.EncodingSemiFlatTypedMap,
		common.EncodingTypedMap,
		common.EncodingTypedMap,
	}

	for _, m := range modes {
		t.Run(fmt.Sprintf("m=%s", m), func(t *testing.T) {
			c := newFlowConverter(m)
			for _, flow := range testutil.GetFlowSamples(t, "../testdata/basic-sample-10-flows.json") {
				spansMsg, err := c.Convert(flow)
				if err != nil {
					t.Error(err)
				}

				spans, ok := spansMsg.Interface().(*traceV1.ResourceSpans)
				if !ok {
					t.Fatal("cannot convert protoreflect.Message to *traceV1.ResourceSpans")
				}
				if spans == nil {
					t.Error("spans shouldn't be nil")
				}
				if spans.Resource == nil {
					t.Error("resource shouldn't be nil")
				}
				if spans.Resource == nil {
					t.Error("resource shouldn't be nil")
				}
				if len(spans.Resource.Attributes) == 0 {
					t.Error("resource attributes shouldn't be empty")
				}
				hasNodeName := false
				for _, attr := range spans.Resource.Attributes {
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
				if len(spans.InstrumentationLibrarySpans) != 1 {
					t.Error("exactly one log record is expected")
				}
				if len(spans.InstrumentationLibrarySpans[0].Spans) != 1 {
					t.Error("exactly one log record is expected")
				}

				span := spans.InstrumentationLibrarySpans[0].Spans[0]

				var payload *commonV1.AnyValue

				hasVersionAttr := false
				hasEncodingAttr := false
				hasPayloadAttr := false
				for _, attr := range span.Attributes {
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

				if len(span.Attributes) != 3 {
					t.Error("attributes should be set when attributes are set")
				}
				if !hasPayloadAttr {
					t.Error("payload should be set")
				}

				f := flow.GetFlow()

				if !strings.HasSuffix(span.Name, fmt.Sprintf("(%s)", f.Summary)) {
					t.Errorf("unexpected name suffix in %q", span.Name)
				}

				if !strings.HasPrefix(span.Name, fmt.Sprintf("%s:", f.IP.Source)) {
					t.Errorf("unexpected name prefix in %q", span.Name)
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
