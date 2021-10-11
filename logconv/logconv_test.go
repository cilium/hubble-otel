package logconv_test

import (
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	logsV1 "go.opentelemetry.io/proto/otlp/logs/v1"

	"github.com/isovalent/hubble-otel/common"
	"github.com/isovalent/hubble-otel/logconv"
	"github.com/isovalent/hubble-otel/testutil"
)

func TestAllLogConvModes(t *testing.T) {
	log := logrus.New()
	// log.SetLevel(logrus.DebugLevel)

	_false := new(bool)
	*_false = false
	_true := new(bool)
	*_true = true

	encodingFormats := common.EncodingFormatsForLogs()
	encodingOptions := []*common.EncodingOptions{
		{TopLevelKeys: _true, LabelsAsMaps: _true, HeadersAsMaps: _true, LogPayloadAsBody: _true},
		{TopLevelKeys: _true, LabelsAsMaps: _true, HeadersAsMaps: _true, LogPayloadAsBody: _false},
		{TopLevelKeys: _true, LabelsAsMaps: _false, HeadersAsMaps: _true, LogPayloadAsBody: _true},
		{TopLevelKeys: _true, LabelsAsMaps: _false, HeadersAsMaps: _true, LogPayloadAsBody: _false},
		{TopLevelKeys: _false, LabelsAsMaps: _true, HeadersAsMaps: _true, LogPayloadAsBody: _true},
		{TopLevelKeys: _false, LabelsAsMaps: _true, HeadersAsMaps: _true, LogPayloadAsBody: _false},
		{TopLevelKeys: _false, LabelsAsMaps: _false, HeadersAsMaps: _true, LogPayloadAsBody: _true},
		{TopLevelKeys: _false, LabelsAsMaps: _false, HeadersAsMaps: _true, LogPayloadAsBody: _false},
		{TopLevelKeys: _true, LabelsAsMaps: _true, HeadersAsMaps: _false, LogPayloadAsBody: _true},
		{TopLevelKeys: _true, LabelsAsMaps: _true, HeadersAsMaps: _false, LogPayloadAsBody: _false},
		{TopLevelKeys: _true, LabelsAsMaps: _false, HeadersAsMaps: _false, LogPayloadAsBody: _true},
		{TopLevelKeys: _true, LabelsAsMaps: _false, HeadersAsMaps: _false, LogPayloadAsBody: _false},
		{TopLevelKeys: _false, LabelsAsMaps: _true, HeadersAsMaps: _false, LogPayloadAsBody: _true},
		{TopLevelKeys: _false, LabelsAsMaps: _true, HeadersAsMaps: _false, LogPayloadAsBody: _false},
		{TopLevelKeys: _false, LabelsAsMaps: _false, HeadersAsMaps: _false, LogPayloadAsBody: _true},
		{TopLevelKeys: _false, LabelsAsMaps: _false, HeadersAsMaps: _false, LogPayloadAsBody: _false},
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

				if options.WithTopLevelKeys() && !options.WithLogPayloadAsBody() &&
					(strings.HasPrefix(options.EncodingFormat(), "JSON") || options.EncodingFormat() == common.EncodingTypedMap) {
					continue
				}
				if err := options.ValidForLogs(); err != nil {
					t.Fatal(err)
				}

				c := logconv.NewFlowConverter(log, options)
				t.Run("("+sample+")/"+options.EncodingFormat()+":"+options.String(), func(t *testing.T) {
					for _, flow := range testutil.GetFlowSamples(t, "../testdata/"+sample) {
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

						payload := testutil.CheckAttributes(t, logRecord.Attributes, *options)

						hasPayloadAttr := payload != nil

						if !c.WithLogPayloadAsBody() {
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

						testutil.CheckPayload(t, payload, c.EncodingFormat())
					}
				})
			}
		}
	}
}
