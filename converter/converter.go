package converter

import (
	"encoding/base64"
	"fmt"
	"strconv"

	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsV1 "go.opentelemetry.io/proto/otlp/logs/v1"
	resourceV1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/cilium/cilium/api/v1/observer"
)

const (
	keyPrefix = "io.cilium.otel."

	FlowLogAttributeLogKindVersion             = keyPrefix + "log_kind_version"
	FlowLogAttributeLogKindVersionFlowV1alpha1 = "flow/v1alpha1"

	FlowLogAttributeLogEncoding           = keyPrefix + "log_encoding"
	DefaultFlowLogEncoding                = FlowLogEncodingJSON
	FlowLogEncodingJSON                   = "JSON"
	FlowLogEncodingJSONBASE64             = "JSON+base64"
	FlowLogEncodingFlatKeyedStringList    = "FKSL"
	FlowLogEncodingSemiFlatKeyedTypedList = "SFKTL"

	FlowLogResourceCiliumClusterID = keyPrefix + "cluster_id"
	FlowLogResourceCiliumNodeName  = keyPrefix + "node_name"
)

func EncodingFormats() []string {
	return []string{
		FlowLogEncodingJSON,
		FlowLogEncodingJSONBASE64,
		FlowLogEncodingFlatKeyedStringList,
		FlowLogEncodingSemiFlatKeyedTypedList,
	}
}

type FlowConverter struct {
	Encoding string
}

func (c *FlowConverter) Convert(hubbleResp *observer.GetFlowsResponse) (*logsV1.ResourceLogs, error) {
	flow := hubbleResp.GetFlow()

	body, err := c.body(hubbleResp)
	if err != nil {
		return nil, err
	}

	return &logsV1.ResourceLogs{
		Resource: &resourceV1.Resource{
			Attributes: newStringAttributes(map[string]string{
				FlowLogResourceCiliumNodeName: flow.GetNodeName(),
			}),
		},
		InstrumentationLibraryLogs: []*logsV1.InstrumentationLibraryLogs{{
			Logs: []*logsV1.LogRecord{{
				TimeUnixNano: uint64(flow.GetTime().AsTime().UnixNano()),
				Attributes: newStringAttributes(map[string]string{
					FlowLogAttributeLogKindVersion: FlowLogAttributeLogKindVersionFlowV1alpha1,
					FlowLogAttributeLogEncoding:    c.Encoding,
				}),
				Body: body,
			}},
		}},
	}, nil
}

func (c *FlowConverter) body(hubbleResp *observer.GetFlowsResponse) (*commonV1.AnyValue, error) {
	var (
		data []byte
		err  error
		v    *commonV1.AnyValue
	)

	switch c.Encoding {
	case FlowLogEncodingJSON, FlowLogEncodingJSONBASE64:
		data, err = hubbleResp.GetFlow().MarshalJSON()
		if err != nil {
			return nil, err
		}

		switch c.Encoding {
		case FlowLogEncodingJSON:
			v = newStringValue(string(data))
		case FlowLogEncodingJSONBASE64:
			v = newStringValue(base64.RawStdEncoding.EncodeToString(data))
		}
	case FlowLogEncodingFlatKeyedStringList, FlowLogEncodingSemiFlatKeyedTypedList:
		var l listAppender
		switch c.Encoding {
		case FlowLogEncodingFlatKeyedStringList:
			l = &flatKeyedList{}
		case FlowLogEncodingSemiFlatKeyedTypedList:
			l = &semiFlatKeyedTypedList{}
		}

		hubbleResp.GetFlow().ProtoReflect().Range(l.newAppender(""))

		v = &commonV1.AnyValue{
			Value: &commonV1.AnyValue_KvlistValue{
				KvlistValue: &commonV1.KeyValueList{
					Values: l.items(),
				},
			},
		}
	}

	return v, nil
}

type listAppender interface {
	newAppender(string) func(protoreflect.FieldDescriptor, protoreflect.Value) bool
	items() []*commonV1.KeyValue
}

type flatKeyedList struct {
	list []*commonV1.KeyValue
}

func (l *flatKeyedList) items() []*commonV1.KeyValue { return l.list }

func (l *flatKeyedList) newAppender(keyPathPrefix string) func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
	return func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		keyPath := fmtKeyPath(keyPathPrefix, fd.JSONName())
		switch {
		case fd.Kind() == protoreflect.MessageKind:
			v.Message().Range(l.newAppender(keyPath))
		case fd.IsList():
			items := v.List()
			for i := 0; i < items.Len(); i++ {
				l.list = append(l.list, &commonV1.KeyValue{
					Key:   fmtKeyPath(keyPath, strconv.Itoa(i)),
					Value: newStringValue(items.Get(i).String()),
				})
			}
		default:
			l.list = append(l.list, &commonV1.KeyValue{
				Key:   keyPath,
				Value: newStringValue(v.String()),
			})
		}
		return true
	}
}

type semiFlatKeyedTypedList struct {
	list []*commonV1.KeyValue
}

func (l *semiFlatKeyedTypedList) items() []*commonV1.KeyValue { return l.list }

func (l *semiFlatKeyedTypedList) newAppender(keyPathPrefix string) func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
	return func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		keyPath := fmtKeyPath(keyPathPrefix, fd.JSONName())
		switch {
		case fd.Kind() == protoreflect.MessageKind:
			v.Message().Range(l.newAppender(keyPath))
		default:
			if item := newValue(true, fd, v); item != nil {
				l.list = append(l.list, &commonV1.KeyValue{
					Key:   keyPath,
					Value: item,
				})
			}
		}
		return true
	}
}

func fmtKeyPath(keyPathPrefix, fieldName string) string {
	// NB: this format assumes that field names don't contain dots or other charcters,
	// which is safe for *flow.Flow, so it's easier to query data as it doesn't
	// result in `[` and `\"` characters being used in the keys; i.e. it's only "IP.source"
	// and not "[\"IP\"][\"source\"]" (which would be less pressumptions, yet harder to
	// query for the user)
	if keyPathPrefix == "" {
		return fieldName
	}
	return fmt.Sprintf("%s.%s", keyPathPrefix, fieldName)
}

func newStringAttributes(attributes map[string]string) []*commonV1.KeyValue {
	results := []*commonV1.KeyValue{}
	for k, v := range attributes {
		results = append(results, &commonV1.KeyValue{
			Key:   k,
			Value: newStringValue(v),
		})
	}
	return results
}

func newStringValue(s string) *commonV1.AnyValue {
	return &commonV1.AnyValue{
		Value: &commonV1.AnyValue_StringValue{
			StringValue: s,
		},
	}
}

func toList(fd protoreflect.FieldDescriptor, v protoreflect.Value) []*commonV1.KeyValue {
	list := []*commonV1.KeyValue{}
	items := v.List()
	for i := 0; i < items.Len(); i++ {
		if item := newValue(false, fd, items.Get(i)); item != nil {
			list = append(list, &commonV1.KeyValue{
				Key:   strconv.Itoa(i),
				Value: item,
			})
		}
	}
	return list
}

func newValue(mayBeAList bool, fd protoreflect.FieldDescriptor, v protoreflect.Value) *commonV1.AnyValue {
	if mayBeAList && fd.IsList() {
		return &commonV1.AnyValue{
			Value: &commonV1.AnyValue_KvlistValue{
				KvlistValue: &commonV1.KeyValueList{
					Values: toList(fd, v),
				},
			},
		}
	}
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return &commonV1.AnyValue{
			Value: &commonV1.AnyValue_BoolValue{
				BoolValue: v.Bool(),
			},
		}
	case protoreflect.EnumKind:
		opts := protojson.MarshalOptions{
			UseProtoNames:  true,
			UseEnumNumbers: false,
		}
		data, err := opts.Marshal(v.Message().Interface())
		if err != nil {
			panic(fmt.Sprintf("unexpected error: %s", err))
		}
		return newStringValue(string(data))
	case protoreflect.Int32Kind,
		protoreflect.Sint32Kind,
		protoreflect.Sfixed32Kind,
		protoreflect.Int64Kind,
		protoreflect.Sint64Kind,
		protoreflect.Sfixed64Kind:
		return &commonV1.AnyValue{
			Value: &commonV1.AnyValue_IntValue{
				IntValue: v.Int(),
			},
		}
	case protoreflect.Uint32Kind,
		protoreflect.Fixed32Kind,
		protoreflect.Uint64Kind,
		protoreflect.Fixed64Kind:
		return &commonV1.AnyValue{
			Value: &commonV1.AnyValue_IntValue{
				IntValue: int64(v.Uint()),
			},
		}
	case
		protoreflect.FloatKind,
		protoreflect.DoubleKind:
		return &commonV1.AnyValue{
			Value: &commonV1.AnyValue_BoolValue{
				BoolValue: v.Bool(),
			},
		}
	case protoreflect.StringKind:
		return newStringValue(v.String())
	case protoreflect.BytesKind:
		return newStringValue(base64.StdEncoding.EncodeToString(v.Bytes()))
	default:
		return nil
	}
}
