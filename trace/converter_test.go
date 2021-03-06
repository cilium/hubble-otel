package trace_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	traceV1 "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/cilium/hubble-otel/common"
	"github.com/cilium/hubble-otel/testutil"
	"github.com/cilium/hubble-otel/trace"
)

func TestAllTraceConvModes(t *testing.T) {
	log := logrus.New()
	// log.SetLevel(logrus.DebugLevel)

	newFlowConverter := func(options *common.EncodingOptions) *trace.FlowConverter {
		t.Helper()

		spanDB, err := os.MkdirTemp("", "hubble-otel-test-trace-cache-")
		if err != nil {
			t.Fatal(err)
		}
		c, err := trace.NewFlowConverter(log, spanDB, options, &common.IncludeFlowTypes{}, common.OTelAttrServiceNameDefaultPrefix, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	_false, _true := testutil.BoolValueRefs()

	encodingFormats := common.EncodingFormatsForTraces()
	encodingOptions := []*common.EncodingOptions{
		// LogPayloadAsBody is irrelevant for traces
		{TopLevelKeys: _true, LabelsAsMaps: _true, HeadersAsMaps: _true},
		{TopLevelKeys: _true, LabelsAsMaps: _false, HeadersAsMaps: _true},
		{TopLevelKeys: _false, LabelsAsMaps: _true, HeadersAsMaps: _true},
		{TopLevelKeys: _false, LabelsAsMaps: _false, HeadersAsMaps: _true},
		{TopLevelKeys: _true, LabelsAsMaps: _true, HeadersAsMaps: _false},
		{TopLevelKeys: _true, LabelsAsMaps: _false, HeadersAsMaps: _false},
		{TopLevelKeys: _false, LabelsAsMaps: _true, HeadersAsMaps: _false},
		{TopLevelKeys: _false, LabelsAsMaps: _false, HeadersAsMaps: _false},
	}

	samples := []string{
		"basic-sample-10-flows.json",
		"basic-sample-330-dns-flows.json",
		"basic-sample-348-http-flows.json",
		"basic-sample-400-icmpv4-flows.json",
		"basic-sample-400-l7-redirected-flows.json",
		"basic-sample-400-tcp-flows.json",
		"basic-sample-400-udp-flows.json",
	}

	for s := range samples {
		for e := range encodingFormats {
			for o := range encodingOptions {
				sample := samples[s]
				options := encodingOptions[o]
				options.Encoding = &encodingFormats[e]

				if options.WithTopLevelKeys() &&
					(strings.HasPrefix(options.EncodingFormat(), "JSON") || options.EncodingFormat() == common.EncodingTypedMap) {
					continue
				}
				if err := options.ValidForTraces(); err != nil {
					t.Fatal(err)
				}

				t.Run("("+sample+")/"+options.EncodingFormat()+":"+options.String(), func(t *testing.T) {
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

						payload := testutil.CheckAttributes(t, span.Attributes, *options)
						testutil.CheckPayload(t, payload, c.EncodingFormat())

						f := flow.GetFlow()

						hasDesc := false
						for _, attr := range span.Attributes {
							if attr.Key == common.AttributeEventDescription {
								hasDesc = true
								desc := attr.Value.GetStringValue()
								if e := fmt.Sprintf("(%s)", f.Summary); !strings.HasSuffix(desc, e) {
									t.Errorf("unexpected name suffix in %q, expected %q", desc, e)
								}

								if f.IP == nil {
									js, _ := f.MarshalJSON()
									t.Logf("skipping flow without IP: %s", js)
									continue
								}

								addrFmt := "%s:"
								if f.L4.GetICMPv4() != nil || f.L4.GetICMPv6() != nil {
									addrFmt = "%s "
								}
								srcPrefix, dstPrefix := fmt.Sprintf(addrFmt, f.IP.Source), fmt.Sprintf(addrFmt, f.IP.Destination)

								if !(strings.HasPrefix(desc, srcPrefix) || strings.HasPrefix(desc, dstPrefix)) {
									t.Errorf("unexpected name prefix in %q, expected %q or %q", desc, srcPrefix, dstPrefix)
								}
							}
						}
						if !hasDesc {
							t.Errorf("missing attribute: %s", common.AttributeEventDescription)
						}

						isKnownSpanName := false
						for _, name := range knownSpanNames {
							if name == span.Name {
								isKnownSpanName = true
							}
						}
						if !isKnownSpanName {
							t.Errorf("unexpectected span name: %s", span.Name)
						}
					}
				})
			}
		}
	}
}

var knownSpanNames = []string{
	"Cilium policy verdict: redirected",
	"DNS request (query types: A)",
	"DNS request (query types: AAAA)",
	"DNS response (query types: A)",
	"DNS response (query types: AAAA)",
	"HTTP GET (request)",
	"HTTP GET (response)",
	"ICMPv4 [to-endpoint]",
	"ICMPv4 [to-overlay]",
	"ICMPv4 [to-stack]",
	"TCP (flags: ACK) [to-endpoint]",
	"TCP (flags: ACK) [to-overlay]",
	"TCP (flags: ACK) [to-proxy]",
	"TCP (flags: ACK) [to-stack]",
	"TCP (flags: ACK, FIN) [to-endpoint]",
	"TCP (flags: ACK, FIN) [to-overlay]",
	"TCP (flags: ACK, FIN) [to-proxy]",
	"TCP (flags: ACK, FIN) [to-stack]",
	"TCP (flags: ACK, PSH) [to-endpoint]",
	"TCP (flags: ACK, PSH) [to-overlay]",
	"TCP (flags: ACK, PSH) [to-proxy]",
	"TCP (flags: ACK, PSH) [to-stack]",
	"TCP (flags: ACK, SYN) [to-endpoint]",
	"TCP (flags: ACK, SYN) [to-overlay]",
	"TCP (flags: ACK, SYN) [to-stack]",
	"TCP (flags: SYN) [to-endpoint]",
	"TCP (flags: SYN) [to-overlay]",
	"TCP (flags: SYN) [to-proxy]",
	"UDP [to-endpoint]",
	"UDP [to-overlay]",
	"UDP [to-proxy]",
}
