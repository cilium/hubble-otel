package common

import (
	"fmt"
	"strconv"

	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type semiFlatTypedMap struct {
	list          []*commonV1.KeyValue
	labelsAsMaps  bool
	headersAsMaps bool
	separator     rune
}

func (l *semiFlatTypedMap) items() []*commonV1.KeyValue { return l.list }

func (l *semiFlatTypedMap) append(k string, v *commonV1.AnyValue) {
	l.list = append(l.list, &commonV1.KeyValue{
		Key:   k,
		Value: v,
	})
}

func (l *semiFlatTypedMap) appendWithDuplicateKeys(k string, v *commonV1.AnyValue) {
	for i := range l.list {
		if l.list[i].Key == k {
			list := l.list[i].Value.GetArrayValue()
			if list == nil {
				panic(fmt.Sprintf("value of existing key %q is not an array", k))
			}
			list.Values = append(list.Values, v)
			return
		}
	}
	l.append(k, v)
}
func (l *semiFlatTypedMap) newLeaf(keyPathPrefix string) leafer {
	return func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		keyPath := fmtKeyPath(keyPathPrefix, string(fd.Name()), l.separator)
		switch {
		case isRegularMessage(fd):
			v.Message().Range(l.newLeaf(keyPath))
		case isMessageList(fd):
			items := v.List()
			headersAsMaps := l.headersAsMaps && fd.FullName() == "flow.HTTP.headers"
			for i := 0; i < items.Len(); i++ {
				item := items.Get(i)
				switch {
				case headersAsMaps:
					k, v, err := parseHeader(item)
					if err != nil {
						panic(err)
					}
					l.appendWithDuplicateKeys(fmtKeyPath(keyPath, k, l.separator), v)
				default:
					items.Get(i).Message().Range(l.newLeaf(fmtKeyPath(keyPath, strconv.Itoa(i), l.separator)))
				}
			}
		default:
			if item := newValue(true, l.labelsAsMaps, l.headersAsMaps, fd, v, nil, ""); item != nil {
				if l.labelsAsMaps && fd.FullName() == "flow.Endpoint.labels" {
					// flatten labels into the main list instead of appending as a new list
					for _, label := range item.GetKvlistValue().GetValues() {
						l.append(fmtKeyPath(keyPath, label.Key, l.separator), label.Value)
					}
				}
				l.append(keyPath, item)
			}
		}
		return true
	}
}
