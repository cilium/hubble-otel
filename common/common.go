package common

import (
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/cilium/cilium/api/v1/observer"
	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/cilium/cilium/api/v1/observer"
)

const (
	keyPrefix = "io.cilium.otel."

	AttributeEventKindVersion             = keyPrefix + "event_kind"
	AttributeEventPayload                 = keyPrefix + "event_payload"
	AttributeEventKindVersionFlowV1alpha1 = "flow/v1alpha1"

	AttributeEventEncoding = keyPrefix + "event_encoding"

	ResourceCiliumClusterID = keyPrefix + "cluster_id"
	ResourceCiliumNodeName  = keyPrefix + "node_name"

	DefaultEncoding          = EncodingTypedMap
	EncodingJSON             = "JSON"
	EncodingJSONBASE64       = "JSON+base64"
	EncodingFlatStringMap    = "FlatStringMap"
	EncodingSemiFlatTypedMap = "SemiFlatTypedMap"
	EncodingTypedMap         = "TypedMap"
)

func EncodingFormats() []string {
	return []string{
		EncodingJSON,
		EncodingJSONBASE64,
		EncodingFlatStringMap,
		EncodingSemiFlatTypedMap,
		EncodingTypedMap,
	}
}
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

func toList(fd protoreflect.FieldDescriptor, v protoreflect.Value) *commonV1.ArrayValue {
	items := v.List()
	list := &commonV1.ArrayValue{
		Values: make([]*commonV1.AnyValue, items.Len()),
	}
	for i := 0; i < items.Len(); i++ {
		if item := newValue(false, fd, items.Get(i)); item != nil {
			list.Values[i] = item
		}
	}
	return list
}

func newValue(mayBeAList bool, fd protoreflect.FieldDescriptor, v protoreflect.Value) *commonV1.AnyValue {
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

type FlowEncoder struct {
	Encoding string
}

func (c *FlowEncoder) ToValue(hubbleResp *observer.GetFlowsResponse) (*commonV1.AnyValue, error) {
	switch c.Encoding {
	case EncodingJSON, EncodingJSONBASE64:
		data, err := hubbleResp.GetFlow().MarshalJSON()
		if err != nil {
			return nil, err
		}

		var s string
		switch c.Encoding {
		case EncodingJSON:
			s = string(data)
		case EncodingJSONBASE64:
			s = base64.RawStdEncoding.EncodeToString(data)
		}
		return newStringValue(s), nil
	case EncodingFlatStringMap, EncodingSemiFlatTypedMap, EncodingTypedMap:
		var mb mapBuilder
		switch c.Encoding {
		case EncodingFlatStringMap:
			mb = &flatStringMap{}
		case EncodingSemiFlatTypedMap:
			mb = &semiFlatTypedMap{}
		case EncodingTypedMap:
			mb = &typedMap{}
		}

		hubbleResp.GetFlow().ProtoReflect().Range(mb.newLeaf(""))

		v := &commonV1.AnyValue{
			Value: &commonV1.AnyValue_KvlistValue{
				KvlistValue: &commonV1.KeyValueList{
					Values: mb.items(),
				},
			},
		}
		return v, nil
	default:
		return nil, fmt.Errorf("unsuported encoding format: %s", c.Encoding)
	}
}

type mapBuilder interface {
	newLeaf(string) func(protoreflect.FieldDescriptor, protoreflect.Value) bool
	items() []*commonV1.KeyValue
}

type flatStringMap struct {
	list []*commonV1.KeyValue
}

func (l *flatStringMap) items() []*commonV1.KeyValue { return l.list }

func (l *flatStringMap) newLeaf(keyPathPrefix string) func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
	return func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		keyPath := fmtKeyPath(keyPathPrefix, fd.JSONName())
		switch {
		case fd.Kind() == protoreflect.MessageKind:
			v.Message().Range(l.newLeaf(keyPath))
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

type semiFlatTypedMap struct {
	list []*commonV1.KeyValue
}

func (l *semiFlatTypedMap) items() []*commonV1.KeyValue { return l.list }

func (l *semiFlatTypedMap) newLeaf(keyPathPrefix string) func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
	return func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		keyPath := fmtKeyPath(keyPathPrefix, fd.JSONName())
		switch {
		case fd.Kind() == protoreflect.MessageKind:
			v.Message().Range(l.newLeaf(keyPath))
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

type typedMap struct {
	list []*commonV1.KeyValue
}

func (l *typedMap) items() []*commonV1.KeyValue { return l.list }

func (l *typedMap) newLeaf(_ string) func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
	return func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.Kind() == protoreflect.MessageKind:
			mb := typedMap{}
			v.Message().Range(mb.newLeaf(""))
			l.list = append(l.list, &commonV1.KeyValue{
				Key: fd.JSONName(),
				Value: &commonV1.AnyValue{
					Value: &commonV1.AnyValue_KvlistValue{
						KvlistValue: &commonV1.KeyValueList{
							Values: mb.items(),
						},
					},
				},
			})
		default:
			if item := newValue(true, fd, v); item != nil {
				l.list = append(l.list, &commonV1.KeyValue{
					Key:   fd.JSONName(),
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
