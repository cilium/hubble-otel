package common

import (
	"strconv"

	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type flatStringMap struct {
	list         []*commonV1.KeyValue
	labelsAsMaps bool
	separator    rune
}

func (l *flatStringMap) items() []*commonV1.KeyValue { return l.list }

func (l *flatStringMap) newLeaf(keyPathPrefix string) leafer {
	return func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		keyPath := fmtKeyPath(keyPathPrefix, string(fd.Name()), l.separator)
		switch {
		case isRegularMessage(fd):
			v.Message().Range(l.newLeaf(keyPath))
		case isMessageList(fd):
			items := v.List()
			labelsAsMap := l.labelsAsMaps && fd.Name() == "labels"
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
			newItem := &commonV1.KeyValue{
				Key: keyPath,
			}
			if formatter, ok := specialCaseFormatter(fd); ok {
				newItem.Value = formatter(v)
			} else {
				newItem.Value = newStringValue(v.String())
			}
			l.list = append(l.list, newItem)
		}
		return true
	}
}
