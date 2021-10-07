package common

import (
	"strconv"

	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type semiFlatTypedMap struct {
	list         []*commonV1.KeyValue
	labelsAsMaps bool
	separator    rune
}

func (l *semiFlatTypedMap) items() []*commonV1.KeyValue { return l.list }

func (l *semiFlatTypedMap) newLeaf(keyPathPrefix string) leafer {
	return func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		keyPath := fmtKeyPath(keyPathPrefix, string(fd.Name()), l.separator)
		switch {
		case isRegularMessage(fd):
			v.Message().Range(l.newLeaf(keyPath))
		case isMessageList(fd):
			items := v.List()
			for i := 0; i < items.Len(); i++ {
				items.Get(i).Message().Range(l.newLeaf(fmtKeyPath(keyPath, strconv.Itoa(i), l.separator)))
			}
		default:
			if item := newValue(true, l.labelsAsMaps, fd, v, nil, ""); item != nil {
				l.list = append(l.list, &commonV1.KeyValue{
					Key:   keyPath,
					Value: item,
				})
			}
		}
		return true
	}
}
