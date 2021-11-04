package common_test

import (
	"testing"

	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"

	flowV1 "github.com/cilium/cilium/api/v1/flow"

	"github.com/cilium/hubble-otel/common"
	"github.com/cilium/hubble-otel/testutil"
)

func TestHTTPAttributes(t *testing.T) {
	samples := []string{
		"basic-sample-348-http-flows.json",
	}

	for s := range samples {
		sample := samples[s]

		t.Run("("+sample+")", func(t *testing.T) {
			for _, f := range testutil.GetFlowSamples(t, "../testdata/"+sample) {
				l7 := f.GetFlow().GetL7()
				http := l7.GetHttp()
				if http == nil {
					t.Error("should be an HTTP flow")
				}

				result := toRaw(&commonV1.AnyValue_KvlistValue{
					KvlistValue: &commonV1.KeyValueList{
						Values: common.GetHTTPAttributes(l7),
					},
				}).(map[string]interface{})
				// t.Logf("result = %#v", result)

				keys := []string{
					common.OTelAttrHTTPMethod,
					common.OTelAttrHTTPURL,
				}

				isResponse := l7.Type == flowV1.L7FlowType_RESPONSE
				if isResponse {
					keys = append(keys, common.OTelAttrHTTPStatusCode)
				}

				for _, k := range keys {
					if _, ok := result[k]; !ok {
						t.Errorf("missing required key %q", k)
					}
				}

				if isResponse {
					code := result[common.OTelAttrHTTPStatusCode]
					if v, ok := code.(int64); !ok {
						t.Errorf("top-level attribute %q is %T, but should be int64", common.OTelAttrHTTPStatusCode, code)
					} else {
						if v != int64(http.Code) {
							t.Errorf("value of top-level attribute %q is %d, should be %d", common.OTelAttrHTTPStatusCode, v, int64(http.Code))
						}
					}
				}

				topLevelHeaderMappings := map[string]struct{}{
					common.OTelAttrHTTPHost:      {},
					common.OTelAttrHTTPUserAgent: {},
				}
				for _, header := range http.Headers {
					k := common.NormaliseHeaderKey(header.Key)
					if _, ok := topLevelHeaderMappings["http."+k]; ok {
						if v, ok := result["http."+k]; !ok {
							t.Errorf("header %q is not mappend to a top-level attribute", header.Key)
						} else if v.(string) != header.Value {
							t.Errorf("value of header %q doesn't match value of mapped top-level attribute (expected: %q, have: %v)", header.Key, header.Value, v)
						}
					} else {
						switch l7.Type {
						case flowV1.L7FlowType_REQUEST:
							checkHeader(t, common.OTelAttrHTTPRequestHeader+k, header.Value, result)
						case flowV1.L7FlowType_RESPONSE:
							checkHeader(t, common.OTelAttrHTTPResponseHeader+k, header.Value, result)
						default:
							t.Error("unexpected L7 type")
						}
					}
				}

				switch http.Protocol {
				case "HTTP/1.1":
					if v, ok := result[common.OTelAttrHTTPFlavor]; !ok {
						t.Errorf("missing required attribute %q", common.OTelAttrHTTPFlavor)
					} else if v != "1.1" {
						t.Errorf("unexpected value of attribute %q: %s", common.OTelAttrHTTPFlavor, v)
					}
				default:
					t.Errorf("untetested HTTP protocol: %s", http.Protocol)
				}
			}
		})
	}
}

func checkHeader(t *testing.T, k, v string, result map[string]interface{}) {
	if values, ok := result[k]; !ok {
		t.Errorf("%q is missing", k)
	} else if values, ok := values.([]interface{}); ok {
		found := false
		for i := range values {
			if values[i].(string) == v {
				found = true
			}
		}
		if !found {
			t.Errorf("value of %q doesn't contain expected value (expected: %q, have: %v)", k, v, values)
		}
	} else {
		t.Errorf("value of %q is not a list", k)
	}
}
