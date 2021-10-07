package common

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	timestamp "google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cilium/cilium/api/v1/observer"
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

type leafer func(protoreflect.FieldDescriptor, protoreflect.Value) bool

type mapBuilder interface {
	newLeaf(string) leafer
	items() []*commonV1.KeyValue
}

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

		data, err := MarshalJSON(hubbleResp.GetFlow())
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

func isRegularMessage(fd protoreflect.FieldDescriptor) bool {
	return fd.Kind() == protoreflect.MessageKind &&
		!isSpecialCase(fd) &&
		(fd.IsMap() || fd.Cardinality() == protoreflect.Optional)
}

func isMessageList(fd protoreflect.FieldDescriptor) bool {
	return fd.Kind() == protoreflect.MessageKind &&
		(fd.Cardinality() == protoreflect.Repeated || fd.Cardinality() == protoreflect.Required)
}

type specialFomatter func(protoreflect.Value) *commonV1.AnyValue

var specialCases = map[protoreflect.FullName]specialFomatter{
	"google.protobuf.Timestamp": formatTimestamp,
	"google.protobuf.BoolValue": formatBool,
}

func specialCaseFormatter(fd protoreflect.FieldDescriptor) (specialFomatter, bool) {
	fdm := fd.Message()
	if fdm == nil {
		return nil, false
	}
	formatter, ok := specialCases[fdm.FullName()]
	return formatter, ok
}

func isSpecialCase(fd protoreflect.FieldDescriptor) bool {
	_, ok := specialCaseFormatter(fd)
	return ok
}

// formatTimestamp handles google.protobuf.Timestamp values, as these are not
// something protoreflect automatically understands
func formatTimestamp(v protoreflect.Value) *commonV1.AnyValue {
	ts := &timestamp.Timestamp{}
	v.Message().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch fd.JSONName() {
		case "seconds":
			ts.Seconds = v.Int()
		case "nanos":
			ts.Nanos = int32(v.Int())
		}
		return true
	})
	data, err := MarshalJSON(ts)
	if err != nil {
		return nil
	}
	// the result happens to be a quoted JSON string, so trim the quotes...
	// (it's safe to do here as the timestamp format won't contain extra quotes)
	return newStringValue(strings.Trim(string(data), "\""))
}

// formatBool handles google.protobuf.BoolValue values, as these are not
// something protoreflect automatically understands
func formatBool(v protoreflect.Value) *commonV1.AnyValue {
	// in theore the value could be unset, but that doesn't actually need to be handled,
	// as in the the case when the field is unset, this logic won't be called at all
	var result bool
	v.Message().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.JSONName() == "value" {
			result = v.Bool()
		}
		return true
	})
	return &commonV1.AnyValue{
		Value: &commonV1.AnyValue_BoolValue{
			BoolValue: result,
		},
	}
}

var jsonMarshaller = &protojson.MarshalOptions{
	AllowPartial:    false,
	UseProtoNames:   true,
	UseEnumNumbers:  false,
	EmitUnpopulated: false,
}

func MarshalJSON(m proto.Message) ([]byte, error) {
	return jsonMarshaller.Marshal(m)
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
		return keyPathPrefix + string(separator) + fieldName
	default:
		return keyPathPrefix + string(separator) + fieldName
	}
}
