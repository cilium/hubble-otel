package receiver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configtest"
	"go.opentelemetry.io/collector/consumer/consumertest"
)

func TestCreateDefaultConfig(t *testing.T) {
	cfg := createDefaultConfig()
	assert.NotNil(t, cfg, "failed to create default config")
	assert.NoError(t, configtest.CheckConfigStruct(cfg))
}

func TestCreateReceiver(t *testing.T) {
	cfg := createDefaultConfig()

	settings := componenttest.NewNopReceiverCreateSettings()

	tracesReceiver, err := createTracesReceiver(context.Background(), settings, cfg, consumertest.NewNop())
	assert.NoError(t, err)
	assert.NotNil(t, tracesReceiver)

	logsReceiver, err := createLogsReceiver(context.Background(), settings, cfg, consumertest.NewNop())
	assert.NoError(t, err)
	assert.NotNil(t, logsReceiver)
}
