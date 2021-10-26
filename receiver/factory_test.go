package receiver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configtest"
)

func TestCreateDefaultConfig(t *testing.T) {
	cfg := createDefaultConfig()
	assert.NotNil(t, cfg, "failed to create default config")
	assert.NoError(t, configtest.CheckConfigStruct(cfg))
}

func TestCreateReceiver(t *testing.T) {
	cfg := createDefaultConfig()

	creationSet := componenttest.NewNopReceiverCreateSettings()
	tracesReceiver, _ := createTracesReceiver(context.Background(), creationSet, cfg, nil)
	assert.NotNil(t, tracesReceiver)
	logsReceiver, _ := createLogsReceiver(context.Background(), creationSet, cfg, nil)
	assert.NotNil(t, logsReceiver)
}
