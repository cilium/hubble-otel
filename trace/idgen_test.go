package trace_test

import (
	"io/ioutil"
	"testing"

	badger "github.com/dgraph-io/badger/v3"

	"github.com/cilium/hubble-otel/testutil"
	"github.com/cilium/hubble-otel/trace"
)

func TestTraceCache(t *testing.T) {
	dir, err := ioutil.TempDir("", "badger")
	if err != nil {
		t.Fatal(err)
	}

	tc, err := trace.NewTraceCache(badger.DefaultOptions(dir), 0)
	if err != nil {
		t.Fatal(err)
	}

	tc.Strict = true

	defer tc.Delete()

	traces := map[string]struct{}{}
	spans := map[string]struct{}{}
	linkedSpans := map[string]struct{}{}
	nonUniqueSpans := 0

	totalFlows := 0
	for _, flow := range testutil.GetFlowSamples(t, "../testdata/2021-10-04-sample-flows-istio-gke-l7/1.json") {
		ctx, link, err := tc.GetSpanContext(flow.GetFlow(), true)
		if err != nil {
			t.Error(err)
		}

		totalFlows++

		if traceID := ctx.TraceID(); traceID.IsValid() {
			traces[traceID.String()] = struct{}{}
			//t.Logf("traceID %v is valid", ids.TraceID)
		} else {
			t.Errorf("traceID %v is invalid", traceID)
		}
		if spanID := ctx.SpanID(); spanID.IsValid() {
			if _, ok := spans[spanID.String()]; ok {
				nonUniqueSpans++
			}
			spans[spanID.String()] = struct{}{}
			//t.Logf("spanID %v is valid", ids.SpanID)
		} else {
			t.Errorf("spanID %v is invalid", spanID)
		}
		if link != nil && link.SpanID().IsValid() {
			linkedSpans[link.SpanID().String()] = struct{}{}
		}
	}

	t.Logf("%d traces, %d spans", len(traces), len(spans))

	if l, e := len(traces), 4052; l != e {
		t.Errorf("unexpected number of traces generated (have: %d, expected %d)", l, e)
	}
	if l, e := nonUniqueSpans, 141; l != e {
		t.Errorf("unexpected number of non-unique spans (have: %d, expected %d)", l, e)
	}
	if l, e := len(spans), totalFlows-nonUniqueSpans; l != e {
		t.Errorf("unexpected number of spans generated (have: %d, expected %d)", l, e)
	}
	if l, e := len(linkedSpans), 34; l != e {
		t.Errorf("unexpected number of parent spans (have: %d, expected %d)", l, e)
	}
}
