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

func toList(fd protoreflect.FieldDescriptor, v protoreflect.Value, mb mapBuilder, newLeafKeyPrefix string) *commonV1.ArrayValue {
	items := v.List()
	list := &commonV1.ArrayValue{
		Values: make([]*commonV1.AnyValue, items.Len()),
	}
	for i := 0; i < items.Len(); i++ {
		if item := newValue(false, false, fd, items.Get(i), mb, newLeafKeyPrefix); item != nil {
			list.Values[i] = item
		}
	}
	return list
}

func newValue(mayBeAList bool, labelsAsMaps bool, fd protoreflect.FieldDescriptor, v protoreflect.Value, mb mapBuilder, newLeafKeyPrefix string) *commonV1.AnyValue {
	if mayBeAList && (fd.Cardinality() == protoreflect.Repeated || fd.Cardinality() == protoreflect.Required) {
		if labelsAsMaps && fd.Name() == "labels" {
			items := v.List()
			labels := &commonV1.KeyValueList{
				Values: make([]*commonV1.KeyValue, items.Len()),
			}
			for i := 0; i < items.Len(); i++ {
				k, v, err := parseLabel(items.Get(i).String())
				if err != nil {
					panic(err)
				}
				labels.Values = append(labels.Values, &commonV1.KeyValue{
					Key:   k,
					Value: newStringValue(v),
				})
			}
			return &commonV1.AnyValue{
				Value: &commonV1.AnyValue_KvlistValue{
					KvlistValue: labels,
				},
			}
		}
		return &commonV1.AnyValue{
			Value: &commonV1.AnyValue_ArrayValue{
				ArrayValue: toList(fd, v, mb, newLeafKeyPrefix),
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
		return newStringValue(string(fd.Enum().Values().ByNumber(v.Enum()).Name()))
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
