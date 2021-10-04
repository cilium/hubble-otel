package traceconv_test

import (
	"io/ioutil"
	"testing"

	badger "github.com/dgraph-io/badger/v3"

	"github.com/isovalent/hubble-otel/testutil"
	"github.com/isovalent/hubble-otel/traceconv"
)

func TestTraceCache(t *testing.T) {
	dir, err := ioutil.TempDir("", "badger")
	if err != nil {
		t.Fatal(err)
	}

	tc, err := traceconv.NewTraceCache(badger.DefaultOptions(dir))
	if err != nil {
		t.Fatal(err)
	}

	tc.Strict = true

	defer tc.Delete()

	traces := map[string]struct{}{}
	spans := map[string]struct{}{}

	for _, flow := range testutil.GetFlowSamples(t, "../testdata/2021-10-04-sample-flows-istio-gke-l7/1.json") {
		ids, err := tc.GetIDs(flow.GetFlow())
		if err != nil {
			t.Error(err)
		}

		if ids.TraceID.IsValid() {
			traces[ids.TraceID.String()] = struct{}{}
			t.Logf("traceID %v is valid", ids.TraceID)
		} else {
			t.Errorf("traceID %v is invalid", ids.TraceID)
		}
		if ids.SpanID.IsValid() {
			spans[ids.SpanID.String()] = struct{}{}
			t.Logf("spanID %v is valid", ids.SpanID)
		} else {
			t.Errorf("spanID %v is invalid", ids.SpanID)
		}
	}

	t.Logf("%d traces, %d spans", len(traces), len(spans))

	if l, e := len(traces), 4083; l != e {
		t.Errorf("unexpected number of traces generated (have: %d, expected %d)", l, e)
	}
	if l, e := len(spans), 40000; l != e {
		t.Errorf("unexpected number of spans generated (have: %d, expected %d)", l, e)
	}
}
