package common

import (
	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type typedMap struct {
	list         []*commonV1.KeyValue
	labelsAsMaps bool
}

func (l *typedMap) items() []*commonV1.KeyValue { return l.list }

func (l *typedMap) newLeaf(_ string) leafer {
	return func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case isRegularMessage(fd):
			mb := &typedMap{}
			item := &commonV1.AnyValue{}
			v.Message().Range(mb.newLeaf(""))
			item.Value = &commonV1.AnyValue_KvlistValue{
				KvlistValue: &commonV1.KeyValueList{
					Values: mb.items(),
				},
			}
			l.list = append(l.list, &commonV1.KeyValue{
				Key:   string(fd.Name()),
				Value: item,
			})
		default:
			if item := newValue(true, l.labelsAsMaps, fd, v, &typedMap{}, ""); item != nil {
				l.list = append(l.list, &commonV1.KeyValue{
					Key:   string(fd.Name()),
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
