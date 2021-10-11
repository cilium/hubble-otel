package common

import (
	"strings"

	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"

	flowV1 "github.com/cilium/cilium/api/v1/flow"
)

func GetHTTPAttributes(l7 *flowV1.Layer7) []*commonV1.KeyValue {
	http := l7.GetHttp()
	if http == nil {
		return nil
	}

	base := map[string]string{
		"http.method": http.Method,
		"http.url":    http.Url,
	}

	switch http.Protocol {
	case "HTTP/1.0":
		base["http.flavor"] = "1.0"
	case "HTTP/1.1":
		base["http.flavor"] = "1.1"
	case "HTTP/2.0":
		base["http.flavor"] = "2.0"
	case "SPDY":
		base["http.flavor"] = "SPDY"
	case "QUIC":
		base["http.flavor"] = "QUIC"
	}

	for _, header := range http.Headers {
		k := NormaliseHeaderKey(header.Key)
		// this is duplicate of cilium.flow_event.l7.http.headers,
		// however key format is very nuanced, so keeping both
		// copies is deemed reasonable

		switch k {
		case "host":
			base["http.host"] = header.Value
			continue
		case "user_agent":
			base["http.user_agent"] = header.Value
			continue
		}

		switch l7.Type {
		case flowV1.L7FlowType_REQUEST:
			base["http.request.header."+k] = header.Value
		case flowV1.L7FlowType_RESPONSE:
			base["http.response.header."+k] = header.Value
		}
	}

	attributes := NewStringAttributes(base)

	if http.Code != 0 {
		attributes = append(attributes, &commonV1.KeyValue{
			Key: "http.status_code",
			Value: &commonV1.AnyValue{
				Value: &commonV1.AnyValue_IntValue{
					IntValue: int64(http.Code),
				},
			},
		})
	}

	return attributes
}

func NormaliseHeaderKey(k string) string {
	return strings.ReplaceAll(strings.ToLower(k), "-", "_")
}
