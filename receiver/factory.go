package receiver

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver/receiverhelper"

	"github.com/cilium/hubble-otel/common"
)

const (
	typeStr = "hubble"
)

var receivers = make(map[config.Receiver]*hubbleReceiver)

func getReceiver(cfg config.Receiver, settings component.ReceiverCreateSettings) *hubbleReceiver {
	if r, ok := receivers[cfg]; ok {
		return r
	}
	r := newHubbleReceiver(cfg.(*Config), settings)
	receivers[cfg] = r
	return r
}
func NewFactory() component.ReceiverFactory {
	return receiverhelper.NewFactory(
		typeStr,
		createDefaultConfig,
		receiverhelper.WithTraces(createTracesReceiver),
		receiverhelper.WithLogs(createLogsReceiver))
}

func createDefaultConfig() config.Receiver {
	_true, _false := new(bool), new(bool)
	*_true, *_false = true, false

	defaultTraceEncoding, defaultLogEncoding := common.DefaultTraceEncoding, common.DefaultLogEncoding

	return &Config{
		ReceiverSettings: config.NewReceiverSettings(config.NewComponentID(typeStr)),
		BufferSize:       2048,
		FlowEncodingOptions: FlowEncodingOptions{
			Traces: common.EncodingOptions{
				Encoding:      &defaultTraceEncoding,
				LabelsAsMaps:  _true,
				HeadersAsMaps: _true,
				TopLevelKeys:  _true,
			},
			Logs: common.EncodingOptions{
				Encoding:         &defaultLogEncoding,
				LabelsAsMaps:     _true,
				HeadersAsMaps:    _true,
				TopLevelKeys:     _false,
				LogPayloadAsBody: _false,
			},
		},
	}
}

func createTracesReceiver(
	_ context.Context,
	settings component.ReceiverCreateSettings,
	cfg config.Receiver,
	nextConsumer consumer.Traces,
) (component.TracesReceiver, error) {
	r := getReceiver(cfg, settings)
	if err := r.registerTraceConsumer(nextConsumer); err != nil {
		return nil, err
	}
	return r, nil
}

func createLogsReceiver(
	_ context.Context,
	settings component.ReceiverCreateSettings,
	cfg config.Receiver,
	nextConsumer consumer.Logs,
) (component.LogsReceiver, error) {
	r := getReceiver(cfg, settings)
	if err := r.registerLogsConsumer(nextConsumer); err != nil {
		return nil, err
	}
	return r, nil
}
