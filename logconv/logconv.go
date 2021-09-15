package logconv

import (
	"encoding/base64"
	"fmt"
	"strconv"

	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsV1 "go.opentelemetry.io/proto/otlp/logs/v1"
	resourceV1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/cilium/cilium/api/v1/observer"
	"github.com/isovalent/hubble-otel/common"
)

const (
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

type FlowConverter struct {
	Encoding      string
	UseAttributes bool
}

func NewFlowConverter(encoding string, useAttributes bool) *FlowConverter {
	return &FlowConverter{
		Encoding:      encoding,
		UseAttributes: useAttributes,
	}
}
func (c *FlowConverter) Convert(hubbleResp *observer.GetFlowsResponse) (protoreflect.Message, error) {
	flow := hubbleResp.GetFlow()

	v, err := c.toValue(hubbleResp)
	if err != nil {
		return nil, err
	}

	logRecord := &logsV1.LogRecord{
		TimeUnixNano: uint64(flow.GetTime().AsTime().UnixNano()),
		Attributes: common.NewStringAttributes(map[string]string{
			common.AttributeEventKindVersion: common.AttributeEventKindVersionFlowV1alpha1,
			common.AttributeEventEncoding:    c.Encoding,
		}),
	}

	resourceLogs := &logsV1.ResourceLogs{
		Resource: &resourceV1.Resource{
			Attributes: common.NewStringAttributes(map[string]string{
				common.ResourceCiliumNodeName: flow.GetNodeName(),
			}),
		},
		InstrumentationLibraryLogs: []*logsV1.InstrumentationLibraryLogs{{
			Logs: []*logsV1.LogRecord{logRecord},
		}},
	}

	if c.UseAttributes {
		logRecord.Attributes = append(logRecord.Attributes, &commonV1.KeyValue{
			Key:   common.AttributeEventPayload,
			Value: v,
		})
	} else {
		logRecord.Body = v
	}

	return resourceLogs.ProtoReflect(), nil
}

func (c *FlowConverter) toValue(hubbleResp *observer.GetFlowsResponse) (*commonV1.AnyValue, error) {
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
		return common.NewStringValue(s), nil
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
					Value: common.NewStringValue(items.Get(i).String()),
				})
			}
		default:
			l.list = append(l.list, &commonV1.KeyValue{
				Key:   keyPath,
				Value: common.NewStringValue(v.String()),
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
			if item := common.NewValue(true, fd, v); item != nil {
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
			if item := common.NewValue(true, fd, v); item != nil {
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
