package common

import (
	"strconv"

	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type flatStringMap struct {
	list          []*commonV1.KeyValue
	labelsAsMaps  bool
	headersAsMaps bool
	separator     rune
}

func (l *flatStringMap) items() []*commonV1.KeyValue { return l.list }

func (l *flatStringMap) append(k string, v *commonV1.AnyValue) {
	l.list = append(l.list, &commonV1.KeyValue{
		Key:   k,
		Value: v,
	})
}

func (l *flatStringMap) newLeaf(keyPathPrefix string) leafer {
	return func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		keyPath := fmtKeyPath(keyPathPrefix, string(fd.Name()), l.separator)
		switch {
		case isRegularMessage(fd):
			v.Message().Range(l.newLeaf(keyPath))
		case isList(fd):
			items := v.List()
			labelsAsMap := l.labelsAsMaps && fd.FullName() == "flow.Endpoint.labels"
			headersAsMaps := l.headersAsMaps && fd.FullName() == "flow.HTTP.headers"
			messageList := isMessageList(fd)
			for i := 0; i < items.Len(); i++ {
				item := items.Get(i)
				switch {
				case labelsAsMap:
					k, v, err := parseLabel(item)
					if err != nil {
						panic(err)
					}
					l.append(fmtKeyPath(keyPath, k, l.separator), newStringValue(v))
				case messageList && !headersAsMaps:
					item.Message().Range(l.newLeaf(fmtKeyPath(keyPath, strconv.Itoa(i), l.separator)))
				case messageList && headersAsMaps:
					k, v, err := parseHeader(item)
					if err != nil {
						panic(err)
					}
					l.append(fmtKeyPath(keyPath, k, l.separator), newStringValue(v))
				default:
					l.append(fmtKeyPath(keyPath, strconv.Itoa(i), l.separator), newStringValue(item.String()))
				}
			}
		default:
			if formatter, ok := specialCaseFormatter(fd); ok {
				l.append(keyPath, formatter(v))
			} else {
				l.append(keyPath, newStringValue(v.String()))
			}
		}
		return true
	}
}
