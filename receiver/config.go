package receiver

import (
	"errors"

	"go.opentelemetry.io/collector/config"
	"go.opentelemetry.io/collector/config/configtls"

	"github.com/isovalent/hubble-otel/common"
)

type Config struct {
	config.ReceiverSettings    `mapstructure:",squash"`
	configtls.TLSClientSetting `mapstructure:"tls,omitempty"`

	Endpoint   string `mapstructure:"endpoint"`
	BufferSize int    `mapstructure:"buffer_size"`

	FlowEncodingOptions FlowEncodingOptions `mapstructure:"flow_encoding_options"`
}

type FlowEncodingOptions struct {
	Traces common.EncodingOptions `mapstructure:"traces"`
	Logs   common.EncodingOptions `mapstructure:"logs"`
}

var _ config.Receiver = (*Config)(nil)

func (cfg Config) Validate() error {
	if cfg.Endpoint == "" {
		return errors.New("hubble endpoint must be specified")
	}
	if err := cfg.FlowEncodingOptions.Traces.ValidForTraces(); err != nil {
		return err
	}
	if err := cfg.FlowEncodingOptions.Logs.ValidForLogs(); err != nil {
		return err
	}
	return nil
}
