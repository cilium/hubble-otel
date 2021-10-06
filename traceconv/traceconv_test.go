package traceconv_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	traceV1 "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/isovalent/hubble-otel/common"
	"github.com/isovalent/hubble-otel/testutil"
	"github.com/isovalent/hubble-otel/traceconv"
)

func TestAllModes(t *testing.T) {
	log := logrus.New()
	// log.SetLevel(logrus.DebugLevel)

	newFlowConverter := func(options common.EncodingOptions) *traceconv.FlowConverter {
		t.Helper()

		spanDB, err := os.MkdirTemp("", "hubble-otel-test-trace-cache-")
		if err != nil {
			t.Fatal(err)
		}
		c, err := traceconv.NewFlowConverter(log.WithField("encodingOptions", options.String()).Logger, spanDB, options)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	encodingFormats := common.EncodingFormatsForTraces()
	encodingOptions := []common.EncodingOptions{
		// LogPayloadAsBody is irrelevant for traces
		{TopLevelKeys: true, LabelsAsMaps: true},
		{TopLevelKeys: true, LabelsAsMaps: false},
		{TopLevelKeys: false, LabelsAsMaps: true},
		{TopLevelKeys: false, LabelsAsMaps: false},
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
				options.Encoding = encodingFormats[e]

				if options.TopLevelKeys &&
					(strings.HasPrefix(options.Encoding, "JSON") || options.Encoding == common.EncodingTypedMap) {
					continue
				}
				if err := options.ValidForTraces(); err != nil {
					t.Fatal(err)
				}

				t.Run("("+sample+")/"+options.Encoding+":"+options.String(), func(t *testing.T) {
					c := newFlowConverter(options)
					for _, flow := range testutil.GetFlowSamples(t, "../testdata/"+sample) {
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

						testutil.CheckResource(t, spans.Resource, flow)

						if len(spans.InstrumentationLibrarySpans) != 1 {
							t.Error("exactly one log record is expected")
						}
						if len(spans.InstrumentationLibrarySpans[0].Spans) != 1 {
							t.Error("exactly one log record is expected")
						}

						span := spans.InstrumentationLibrarySpans[0].Spans[0]

						payload := testutil.CheckAttributes(t, span.Attributes, options)
						testutil.CheckPayload(t, payload, c.Encoding)

						f := flow.GetFlow()

						if e := fmt.Sprintf("(%s)", f.Summary); !strings.HasSuffix(span.Name, e) {
							t.Errorf("unexpected name suffix in %q, expected %q", span.Name, e)
						}

						srcPrefix, dstPrefix := fmt.Sprintf("%s:", f.IP.Source), fmt.Sprintf("%s:", f.IP.Destination)

						if !(strings.HasPrefix(span.Name, srcPrefix) || strings.HasPrefix(span.Name, dstPrefix)) {
							t.Errorf("unexpected name prefix in %q, expected %q or %q", span.Name, srcPrefix, dstPrefix)
						}
					}
				})
			}
		}
	}
}
