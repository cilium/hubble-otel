package common_test

import (
	"testing"

	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"

	flowV1 "github.com/cilium/cilium/api/v1/flow"

	"github.com/isovalent/hubble-otel/common"
	"github.com/isovalent/hubble-otel/testutil"
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
					"http.method",
					"http.url",
				}

				isResponse := l7.Type == flowV1.L7FlowType_RESPONSE
				if isResponse {
					keys = append(keys, "http.status_code")
				}

				for _, k := range keys {
					if _, ok := result[k]; !ok {
						t.Errorf("missing required key %q", k)
					}
				}

				if isResponse {
					code := result["http.status_code"]
					if v, ok := code.(int64); !ok {
						t.Errorf("top-level attribute %q is %T, but should be int64", "http.status_code", code)
					} else {
						if v != int64(http.Code) {
							t.Errorf("value of top-level attribute %q is %d, should be %d", "http.status_code", v, int64(http.Code))
						}
					}
				}

				topLevelHeaderMappings := map[string]struct{}{
					"http.host":       {},
					"http.user_agent": {},
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
							if v, ok := result["http.request.header."+k]; !ok {
								t.Errorf("request header %q is missing", header.Key)
							} else if v.(string) != header.Value {
								t.Errorf("value of request header %q doesn't match value of corresponding attribute (expected: %q, have: %v)", header.Key, header.Value, v)
							}
						case flowV1.L7FlowType_RESPONSE:
							if v, ok := result["http.response.header."+k]; !ok {
								t.Errorf("response header %q is missing", header.Key)
							} else if v.(string) != header.Value {
								t.Errorf("value of response header %q doesn't match value of corresponding attribute (expected: %q, have: %v)", header.Key, header.Value, v)
							}
						default:
							t.Error("unexpected L7 type")
						}
					}
				}

				switch http.Protocol {
				case "HTTP/1.1":
					if v, ok := result["http.flavor"]; !ok {
						t.Errorf("missing required attribute %q", "http.flavor")
					} else if v != "1.1" {
						t.Errorf("unexpected value of attribute %q: %s", "http.flavor", v)
					}
				default:
					t.Errorf("untetested HTTP protocol: %s", http.Protocol)
				}
			}
		})
	}
}
