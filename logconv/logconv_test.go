package logconv_test

import (
	"fmt"
	"testing"

	logsV1 "go.opentelemetry.io/proto/otlp/logs/v1"

	"github.com/isovalent/hubble-otel/common"
	"github.com/isovalent/hubble-otel/logconv"
	"github.com/isovalent/hubble-otel/testutil"
)

func TestAllModes(t *testing.T) {
	modes := []struct {
		encoding      string
		useAttributes bool
	}{
		{common.EncodingJSON, false},
		{common.EncodingJSONBASE64, false},
		{common.EncodingFlatStringMap, false},
		{common.EncodingFlatStringMap, true},
		{common.EncodingSemiFlatTypedMap, false},
		{common.EncodingSemiFlatTypedMap, true},
		{common.EncodingTypedMap, false},
		{common.EncodingTypedMap, true},
	}

	for _, m := range modes {
		c := logconv.NewFlowConverter(m.encoding, m.useAttributes)
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

				testutil.CheckResource(t, logs.Resource, flow)

				if len(logs.InstrumentationLibraryLogs) != 1 {
					t.Error("exactly one log record is expected")
				}
				if len(logs.InstrumentationLibraryLogs[0].Logs) != 1 {
					t.Error("exactly one log record is expected")
				}

				logRecord := logs.InstrumentationLibraryLogs[0].Logs[0]

				payload := testutil.CheckAttributes(t, logRecord.Attributes, c.Encoding)

				hasPayloadAttr := payload != nil

				if c.UseAttributes {
					if logRecord.Body != nil {
						t.Error("body should be unset when attributes are set")
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

				testutil.CheckPayload(t, payload, c.Encoding)
			}
		})
	}
}
