package receiver

import (
	"context"
	"errors"

	"google.golang.org/grpc/metadata"

	"go.opentelemetry.io/collector/config"
	"go.opentelemetry.io/collector/config/configgrpc"

	"github.com/isovalent/hubble-otel/common"
)

type Config struct {
	config.ReceiverSettings       `mapstructure:",squash"`
	configgrpc.GRPCClientSettings `mapstructure:",squash"`

	BufferSize int `mapstructure:"buffer_size"`

	FlowEncodingOptions FlowEncodingOptions `mapstructure:"flow_encoding_options"`
}

type FlowEncodingOptions struct {
	Traces common.EncodingOptions `mapstructure:"traces"`
	Logs   common.EncodingOptions `mapstructure:"logs"`
}

var _ config.Receiver = (*Config)(nil)

func (cfg *Config) Validate() error {
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

func (cfg *Config) NewOutgoingContext(ctx context.Context) context.Context {
	if cfg.GRPCClientSettings.Headers == nil {
		return ctx
	}
	return metadata.NewOutgoingContext(ctx, metadata.New(cfg.GRPCClientSettings.Headers))
}
