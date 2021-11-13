package receiver

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/metadata"

	"go.opentelemetry.io/collector/config"
	"go.opentelemetry.io/collector/config/configgrpc"

	"github.com/cilium/hubble-otel/common"
)

type Config struct {
	config.ReceiverSettings       `mapstructure:",squash"`
	configgrpc.GRPCClientSettings `mapstructure:",squash"`

	BufferSize int `mapstructure:"buffer_size"`

	FlowEncodingOptions FlowEncodingOptions `mapstructure:"flow_encoding_options"`
	IncludeFlowTypes    IncludeFlowTypes    `mapstructure:"include_flow_types"`

	FallbackServiceNamePrefix string        `mapstructure:"fallback_service_name_prefix"`
	TraceCacheWindow          time.Duration `mapstructure:"trace_cache_window"`
	ParseTraceHeaders         bool          `mapstructure:"parse_trace_headers"`
}

type FlowEncodingOptions struct {
	Traces common.EncodingOptions `mapstructure:"traces"`
	Logs   common.EncodingOptions `mapstructure:"logs"`
}

type IncludeFlowTypes struct {
	Traces common.IncludeFlowTypes `mapstructure:"traces"`
	Logs   common.IncludeFlowTypes `mapstructure:"logs"`
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
	if err := cfg.IncludeFlowTypes.Traces.Validate(); err != nil {
		return err
	}
	if err := cfg.IncludeFlowTypes.Logs.Validate(); err != nil {
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
