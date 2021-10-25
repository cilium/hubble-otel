package hubblereceiver

import (
	"context"

	"github.com/isovalent/hubble-otel/common"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver/receiverhelper"
)

const (
	typeStr = "hubble"
)

// NewFactory creates a new Prometheus receiver factory.
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
	set component.ReceiverCreateSettings,
	cfg config.Receiver,
	nextConsumer consumer.Traces,
) (component.TracesReceiver, error) {
	return &hubbleTracesReceiver{
		hubbleReceiver: hubbleReceiver{
			logger:   set.Logger,
			cfg:      cfg.(*Config),
			consumer: nextConsumer,
		},
	}, nil
}

func createLogsReceiver(
	_ context.Context,
	set component.ReceiverCreateSettings,
	cfg config.Receiver,
	nextConsumer consumer.Logs,
) (component.LogsReceiver, error) {
	return nil, nil
}
