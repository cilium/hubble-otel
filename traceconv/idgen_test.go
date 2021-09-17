package traceconv_test

import (
	"io/ioutil"
	"testing"

	badger "github.com/dgraph-io/badger/v3"

	"github.com/isovalent/hubble-otel/testutil"
	"github.com/isovalent/hubble-otel/traceconv"
)

func TestBadger(t *testing.T) {
	dir, err := ioutil.TempDir("", "badger")
	if err != nil {
		t.Fatal(err)
	}

	tc, err := traceconv.NewTraceCache(badger.DefaultOptions(dir))
	if err != nil {
		t.Fatal(err)
	}

	defer tc.Delete()

	traces := map[string]struct{}{}
	spans := map[string]struct{}{}

	for _, flow := range testutil.GetFlowSamples(t, "../testdata/2021-06-16-sample-flows-istio-gke/1.json") {
		traceID, spanID, err := tc.GetIDs(flow.GetFlow())
		if err != nil {
			t.Error(err)
		}
		if traceID.IsValid() {
			traces[traceID.String()] = struct{}{}
			t.Logf("traceID %v is valid", traceID)
		} else {
			t.Errorf("traceID %v is invalid", traceID)
		}
		if spanID.IsValid() {
			spans[spanID.String()] = struct{}{}
			t.Logf("spanID %v is valid", spanID)
		} else {
			t.Errorf("spanID %v is invalid", spanID)
		}
	}

	t.Logf("%d traces, %d spans", len(traces), len(spans))

	if l, e := len(traces), 2145; l != e {
		t.Errorf("unexpected number of traces generated (have: %d, expected %d)", l, e)
	}
	if l, e := len(spans), 20000; l != e {
		t.Errorf("unexpected number of spans generated (have: %d, expected %d)", l, e)
	}
}
