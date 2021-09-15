package common

import (
	"encoding/base64"

	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	keyPrefix = "io.cilium.otel."

	AttributeEventKindVersion             = keyPrefix + "event_kind"
	AttributeEventPayload                 = keyPrefix + "event_payload"
	AttributeEventKindVersionFlowV1alpha1 = "flow/v1alpha1"

	AttributeEventEncoding = keyPrefix + "event_encoding"

	ResourceCiliumClusterID = keyPrefix + "cluster_id"
	ResourceCiliumNodeName  = keyPrefix + "node_name"
)

func NewStringAttributes(attributes map[string]string) []*commonV1.KeyValue {
	results := []*commonV1.KeyValue{}
	for k, v := range attributes {
		results = append(results, &commonV1.KeyValue{
			Key:   k,
			Value: NewStringValue(v),
		})
	}
	return results
}

func NewStringValue(s string) *commonV1.AnyValue {
	return &commonV1.AnyValue{
		Value: &commonV1.AnyValue_StringValue{
			StringValue: s,
		},
	}
}

func toList(fd protoreflect.FieldDescriptor, v protoreflect.Value) *commonV1.ArrayValue {
	items := v.List()
	list := &commonV1.ArrayValue{
		Values: make([]*commonV1.AnyValue, items.Len()),
	}
	for i := 0; i < items.Len(); i++ {
		if item := NewValue(false, fd, items.Get(i)); item != nil {
			list.Values[i] = item
		}
	}
	return list
}

func NewValue(mayBeAList bool, fd protoreflect.FieldDescriptor, v protoreflect.Value) *commonV1.AnyValue {
	if mayBeAList && fd.IsList() {
		return &commonV1.AnyValue{
			Value: &commonV1.AnyValue_ArrayValue{
				ArrayValue: toList(fd, v),
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
		return NewStringValue(string(fd.Enum().Values().ByNumber(v.Enum()).Name()))
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
		return NewStringValue(v.String())
	case protoreflect.BytesKind:
		return NewStringValue(base64.StdEncoding.EncodeToString(v.Bytes()))
	default:
		return nil
	}
}
