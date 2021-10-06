package common

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/cilium/cilium/api/v1/observer"
	"github.com/sirupsen/logrus"
)

const (
	keyNamespaceCilium = "cilium."

	AttributeEventKindVersion     = keyNamespaceCilium + "event_kind"
	AttributeEventEncoding        = keyNamespaceCilium + "event_encoding"
	AttributeEventEncodingOptions = keyNamespaceCilium + "event_encoding_options"

	AttributeEventKindVersionFlowV1alpha1 = "flow/v1alpha2"

	// in order to comply with the spec, cilium.flow_event is used with flat maps,
	// and cilium.event_object is used to hold JSON-encoded or nested payloads,
	// so that namespace and standalone key collision is avoided
	AttributeFlowEventNamespace = keyNamespaceCilium + "flow_event"
	AttributeEventObject        = keyNamespaceCilium + "event_object"

	ResourceCiliumClusterID = keyNamespaceCilium + "cluster_id"
	ResourceCiliumNodeName  = keyNamespaceCilium + "node_name"

	DefaultLogEncoding       = EncodingTypedMap
	DefaultTraceEncoding     = EncodingSemiFlatTypedMap
	EncodingJSON             = "JSON"
	EncodingJSONBASE64       = "JSON+base64"
	EncodingFlatStringMap    = "FlatStringMap"
	EncodingSemiFlatTypedMap = "SemiFlatTypedMap"
	EncodingTypedMap         = "TypedMap"
)

func EncodingFormatsForLogs() []string {
	return []string{
		EncodingJSON,
		EncodingJSONBASE64,
		EncodingFlatStringMap,
		EncodingSemiFlatTypedMap,
		EncodingTypedMap,
	}
}

func EncodingFormatsForTraces() []string {
	return []string{
		EncodingJSON,
		EncodingJSONBASE64,
		EncodingFlatStringMap,
		EncodingSemiFlatTypedMap,
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
		if item := newValue(false, false, fd, items.Get(i)); item != nil {
			list.Values[i] = item
		}
	}
	return list
}

func newValue(mayBeAList bool, labelsAsMaps bool, fd protoreflect.FieldDescriptor, v protoreflect.Value) *commonV1.AnyValue {
	if mayBeAList && fd.IsList() {
		if labelsAsMaps && fd.JSONName() == "labels" {
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
	EncodingOptions
	Logger *logrus.Logger
}

type EncodingOptions struct {
	Encoding         string
	TopLevelKeys     bool
	LabelsAsMaps     bool
	LogPayloadAsBody bool
}

func (o EncodingOptions) String() string {
	options := []string{}
	if o.TopLevelKeys {
		options = append(options, "TopLevelKeys")
	}
	if o.LabelsAsMaps {
		options = append(options, "LabelsAsMaps")
	}
	if o.LogPayloadAsBody {
		options = append(options, "LogPayloadAsBody")
	}
	return strings.Join(options, ",")
}

func (o EncodingOptions) ValidForLogs() error {
	if err := o.validateFormat("logs", EncodingFormatsForLogs()); err != nil {
		return err
	}
	switch o.Encoding {
	case EncodingJSON, EncodingJSONBASE64, EncodingTypedMap:
		if o.TopLevelKeys && !o.LogPayloadAsBody {
			return fmt.Errorf("option \"TopLevelKeys\" without \"LogPayloadAsBody\" is not compatible with %q encoding", o.Encoding)
		}
	}
	return nil
}

func (o EncodingOptions) ValidForTraces() error {
	if err := o.validateFormat("trace", EncodingFormatsForTraces()); err != nil {
		return err
	}
	switch o.Encoding {
	case EncodingJSON, EncodingJSONBASE64:
		if o.TopLevelKeys {
			return fmt.Errorf("option \"TopLevelKeys\" is not compatible with %q encoding", o.Encoding)
		}
	}
	if o.LogPayloadAsBody {
		return fmt.Errorf("option \"LogPayloadAsBody\" is not compatible with \"trace\" data type")

	}
	return nil
}

func (o EncodingOptions) validateFormat(dataType string, formats []string) error {
	invalidFormat := true
	for _, format := range formats {
		if o.Encoding == format {
			invalidFormat = false
		}
	}
	if invalidFormat {
		return fmt.Errorf("encoding %q is invalid for %s data", o.Encoding, dataType)
	}
	return nil
}

func (c *FlowEncoder) ToValue(hubbleResp *observer.GetFlowsResponse) (*commonV1.AnyValue, error) {
	overrideOptionsWithWarning := func() {
		if c.TopLevelKeys && !c.LogPayloadAsBody {
			if c.Logger != nil {
				c.Logger.Warnf("encoder: disabling \"TopLevelKeys\" option as it's incompatible"+
					" with %q encoding when \"LogPayloadAsBody\" disabled also", c.Encoding)
			}
			c.TopLevelKeys = false
		}
	}

	switch c.Encoding {
	case EncodingJSON, EncodingJSONBASE64:
		overrideOptionsWithWarning()

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
			mb = &flatStringMap{
				labelsAsMaps: c.LabelsAsMaps,
				separator:    '.',
			}
		case EncodingSemiFlatTypedMap:
			mb = &semiFlatTypedMap{
				labelsAsMaps: c.LabelsAsMaps,
				separator:    '.',
			}
		case EncodingTypedMap:
			overrideOptionsWithWarning()

			mb = &typedMap{
				labelsAsMaps: c.LabelsAsMaps,
			}
		}

		topLevel := ""
		if c.TopLevelKeys {
			topLevel = AttributeFlowEventNamespace
		}

		hubbleResp.GetFlow().ProtoReflect().Range(mb.newLeaf(topLevel))

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
	list         []*commonV1.KeyValue
	labelsAsMaps bool
	separator    rune
}

func (l *flatStringMap) items() []*commonV1.KeyValue { return l.list }

func (l *flatStringMap) newLeaf(keyPathPrefix string) func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
	return func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		keyPath := fmtKeyPath(keyPathPrefix, fd.JSONName(), l.separator)
		switch {
		case fd.IsMap():
			v.Message().Range(l.newLeaf(keyPath))
		case fd.IsList():
			items := v.List()
			labelsAsMap := l.labelsAsMaps && fd.JSONName() == "labels"
			for i := 0; i < items.Len(); i++ {
				if labelsAsMap {
					k, v, err := parseLabel(items.Get(i).String())
					if err != nil {
						panic(err)
					}
					l.list = append(l.list, &commonV1.KeyValue{
						Key:   fmtKeyPath(keyPath, k, l.separator),
						Value: newStringValue(v),
					})

				} else {
					l.list = append(l.list, &commonV1.KeyValue{
						Key:   fmtKeyPath(keyPath, strconv.Itoa(i), l.separator),
						Value: newStringValue(items.Get(i).String()),
					})
				}
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
	list         []*commonV1.KeyValue
	labelsAsMaps bool
	separator    rune
}

func (l *semiFlatTypedMap) items() []*commonV1.KeyValue { return l.list }

func (l *semiFlatTypedMap) newLeaf(keyPathPrefix string) func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
	return func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		keyPath := fmtKeyPath(keyPathPrefix, fd.JSONName(), l.separator)
		switch {
		case fd.IsMap():
			v.Message().Range(l.newLeaf(keyPath))
		default:
			if item := newValue(true, l.labelsAsMaps, fd, v); item != nil {
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
	list         []*commonV1.KeyValue
	labelsAsMaps bool
}

func (l *typedMap) items() []*commonV1.KeyValue { return l.list }

func (l *typedMap) newLeaf(_ string) func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
	return func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsMap():
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
			if item := newValue(true, l.labelsAsMaps, fd, v); item != nil {
				l.list = append(l.list, &commonV1.KeyValue{
					Key:   fd.JSONName(),
					Value: item,
				})
			}
		}
		return true
	}
}

func fmtKeyPath(keyPathPrefix, fieldName string, separator rune) string {
	// NB: this format assumes that field names don't contain dots or other charcters,
	// which is safe for *flow.Flow, so it's easier to query data as it doesn't
	// result in `[` and `\"` characters being used in the keys; i.e. it's only "IP.source"
	// and not "[\"IP\"][\"source\"]" (which would be less pressumptions, yet harder to
	// query for the user)
	switch keyPathPrefix {
	case "":
		return fieldName
	case AttributeFlowEventNamespace:
		return keyPathPrefix + fieldName
	default:
		return keyPathPrefix + string(separator) + fieldName
	}
}

func parseLabel(label string) (string, string, error) {
	parts := strings.Split(label, "=")
	switch len(parts) {
	case 2:
		return parts[0], parts[1], nil
	case 1:
		return parts[0], "", nil
	default:
		return "", "", fmt.Errorf("cannot parse label %q, as it's not in \"k=v\" format", label)
	}
}
