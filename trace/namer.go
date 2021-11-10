package trace

import (
	"bytes"
	"strings"

	flowV1 "github.com/cilium/cilium/api/v1/flow"
	hubbleObserver "github.com/cilium/cilium/api/v1/observer"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	hubblePrinter "github.com/cilium/hubble/pkg/printer"
)

func (c *FlowConverter) getSpanName(f *flowV1.Flow) string {
	eventType := f.GetEventType()
	namer, ok := spanNamers[eventType.GetType()]
	if ok {
		return namer(f, uint8(eventType.GetSubType()))
	}
	return "internal Cilium event: " + eventType.String()
}

var spanNamers = map[int32]func(*flowV1.Flow, uint8) string{

	monitorAPI.MessageTypeTrace: func(f *flowV1.Flow, eventSubType uint8) string {
		observationPoint := "[" + monitorAPI.TraceObservationPoint(eventSubType) + "]"
		if l4 := f.GetL4(); l4 != nil {
			switch l4.GetProtocol().(type) {
			case *flowV1.Layer4_ICMPv4:
				return "ICMPv4 " + observationPoint
			case *flowV1.Layer4_ICMPv6:
				return "ICMPv6 " + observationPoint
			case *flowV1.Layer4_TCP:
				flags := l4.GetTCP().Flags
				fl := []string{}
				if flags.ACK {
					fl = append(fl, "ACK")
				}
				if flags.CWR {
					fl = append(fl, "CWR")
				}
				if flags.ECE {
					fl = append(fl, "ECE")
				}
				if flags.FIN {
					fl = append(fl, "FIN")
				}
				if flags.NS {
					fl = append(fl, "NS")
				}
				if flags.PSH {
					fl = append(fl, "PSH")
				}
				if flags.RST {
					fl = append(fl, "RST")
				}
				if flags.SYN {
					fl = append(fl, "SYN")
				}
				if flags.URG {
					fl = append(fl, "URG")
				}
				return "TCP (flags: " + strings.Join(fl, ", ") + ") " + observationPoint
			case *flowV1.Layer4_UDP:
				return "UDP " + observationPoint
			default:
				return "Cilium L4 event " + observationPoint
			}
		}
		return "unknown Cilium trace event"
	},

	monitorAPI.MessageTypeAccessLog: func(f *flowV1.Flow, _ uint8) string {
		if l7 := f.GetL7(); l7 != nil {
			t := strings.ToLower(l7.Type.String())
			switch l7.GetRecord().(type) {
			case *flowV1.Layer7_Http:
				return "HTTP " + l7.GetHttp().Method + " (" + t + ")"
			case *flowV1.Layer7_Dns:
				return "DNS " + t + " (query types: " + strings.Join(l7.GetDns().Qtypes, " ") + ")"
			case *flowV1.Layer7_Kafka:
				return "Kafka" + t
			default:
				return "Cilium L7 event (type: " + t + ")"
			}
		}
		return "unknown Cilium access log event"
	},

	monitorAPI.MessageTypeDrop: func(_ *flowV1.Flow, eventSubType uint8) string {
		return "Cilium drop event (reason: " + monitorAPI.DropReason(eventSubType) + ")"
	},

	monitorAPI.MessageTypePolicyVerdict: func(f *flowV1.Flow, _ uint8) string {
		verdict := f.GetVerdict()
		name := "Cilium policy verdict: "
		switch verdict {
		case flowV1.Verdict_FORWARDED:
			return name + "forwarded (match type: " + monitorAPI.PolicyMatchType(f.GetPolicyMatchType()).String() + ")"
		case flowV1.Verdict_DROPPED:
			return name + "dropped (reason: " + monitorAPI.DropReason(uint8(f.GetDropReason())) + ")"
		case flowV1.Verdict_AUDIT:
			return name + "audit"
		case flowV1.Verdict_ERROR:
			return name + "error"
		case flowV1.Verdict_VERDICT_UNKNOWN:
			return name + "unknown"
		}
		return "unknown Cilium policy verdict event"
	},
}

func (c *FlowConverter) getSpanDesc(hubbleResp *hubbleObserver.GetFlowsResponse) (string, error) {

	b := bytes.NewBuffer([]byte{})
	p := hubblePrinter.New(
		hubblePrinter.Writer(b),
		hubblePrinter.Compact(),
		hubblePrinter.WithTimeFormat(""),
		hubblePrinter.WithColor("never"),
		hubblePrinter.IgnoreStderr(),
	)
	if err := p.WriteProtoFlow(hubbleResp); err != nil {
		return "", err
	}
	s := strings.TrimSuffix(
		strings.TrimPrefix(b.String(), ": "),
		"\n",
	)
	return s, nil
}
