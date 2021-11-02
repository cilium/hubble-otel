package common

import (
	"encoding/base64"

	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func NewStringAttributes(attributes map[string]string) []*commonV1.KeyValue {
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

func newStringArrayValue(s ...string) *commonV1.AnyValue {
	array := []*commonV1.AnyValue{}
	for _, v := range s {
		array = append(array, newStringValue(v))
	}
	return &commonV1.AnyValue{
		Value: &commonV1.AnyValue_ArrayValue{
			ArrayValue: &commonV1.ArrayValue{
				Values: array,
			},
		},
	}
}

func toList(labelsAsMaps, headersAsMaps bool, fd protoreflect.FieldDescriptor, v protoreflect.Value, mb mapBuilder, newLeafKeyPrefix string) *commonV1.ArrayValue {
	items := v.List()
	list := &commonV1.ArrayValue{
		Values: make([]*commonV1.AnyValue, items.Len()),
	}
	for i := 0; i < items.Len(); i++ {
		if item := newValue(false, labelsAsMaps, headersAsMaps, fd, items.Get(i), mb, newLeafKeyPrefix); item != nil {
			list.Values[i] = item
		}
	}
	return list
}

func listToMap(v protoreflect.Value, converter func(v protoreflect.Value) (string, *commonV1.AnyValue, error)) *commonV1.AnyValue {
	items := v.List()
	m := &commonV1.KeyValueList{
		Values: make([]*commonV1.KeyValue, items.Len()),
	}
	for i := 0; i < items.Len(); i++ {
		k, v, err := converter(items.Get(i))
		if err != nil {
			panic(err)
		}
		m.Values[i] = &commonV1.KeyValue{
			Key:   k,
			Value: v,
		}
	}
	return &commonV1.AnyValue{
		Value: &commonV1.AnyValue_KvlistValue{
			KvlistValue: m,
		},
	}
}

func newValue(assumeList, labelsAsMaps, headersAsMaps bool, fd protoreflect.FieldDescriptor, v protoreflect.Value, mb mapBuilder, newLeafKeyPrefix string) *commonV1.AnyValue {
	if assumeList && isList(fd) {
		if labelsAsMaps && fd.FullName() == "flow.Endpoint.labels" {
			return listToMap(v, parseLabel)
		}
		if headersAsMaps && fd.FullName() == "flow.HTTP.headers" {
			return listToMap(v, parseHeader)
		}
		return &commonV1.AnyValue{
			Value: &commonV1.AnyValue_ArrayValue{
				ArrayValue: toList(labelsAsMaps, headersAsMaps, fd, v, mb, newLeafKeyPrefix),
			},
		}
	}

	if formatter, ok := specialCaseFormatter(fd); ok {
		return formatter(v)
	}

	switch fd.Kind() {
	case protoreflect.BoolKind:
		return &commonV1.AnyValue{
			Value: &commonV1.AnyValue_BoolValue{
				BoolValue: v.Bool(),
			},
		}
	case protoreflect.EnumKind:
		if resolvedEnum := fd.Enum().Values().ByNumber(v.Enum()); resolvedEnum != nil {
			return newStringValue(string(resolvedEnum.Name()))
		}
		return &commonV1.AnyValue{
			Value: &commonV1.AnyValue_IntValue{
				IntValue: int64(v.Enum()),
			},
		}
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
	case protoreflect.FloatKind,
		protoreflect.DoubleKind:
		return &commonV1.AnyValue{
			Value: &commonV1.AnyValue_DoubleValue{
				DoubleValue: v.Float(),
			},
		}
	case protoreflect.StringKind:
		return newStringValue(v.String())
	case protoreflect.BytesKind:
		return newStringValue(base64.StdEncoding.EncodeToString(v.Bytes()))
	case protoreflect.MessageKind:
		if mb == nil {
			return nil
		}
		v.Message().Range(mb.newLeaf(newLeafKeyPrefix))
		return &commonV1.AnyValue{
			Value: &commonV1.AnyValue_KvlistValue{
				KvlistValue: &commonV1.KeyValueList{
					Values: mb.items(),
				},
			},
		}
	default:
		return nil
	}
}
