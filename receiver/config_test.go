package receiver

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config"
	"go.opentelemetry.io/collector/config/configtest"
)

func TestLoadConfig(t *testing.T) {
	_ = os.Setenv("HUBBLE_ENDPOINT", "localhost:4244")
	_ = os.Setenv("NODE_NAME", "localhost")

	factories, err := componenttest.NopFactories()
	assert.NoError(t, err)

	factory := NewFactory()
	factories.Receivers[typeStr] = factory
	cfg, err := configtest.LoadConfigAndValidate(path.Join(".", "testdata", "config.yaml"), factories)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, len(cfg.Receivers), 4)

	r0 := cfg.Receivers[config.NewComponentID(typeStr)]
	r0.(*Config).Endpoint = ""
	assert.Equal(t, r0, factory.CreateDefaultConfig())

	r1 := cfg.Receivers[config.NewComponentIDWithName(typeStr, "customname")].(*Config)
	assert.Equal(t, r1.ReceiverSettings, config.NewReceiverSettings(config.NewComponentIDWithName(typeStr, "customname")))

	r2 := cfg.Receivers[config.NewComponentIDWithName(typeStr, "env")].(*Config)
	assert.Equal(t, r2.Endpoint, "localhost:4244")

	r3 := cfg.Receivers[config.NewComponentIDWithName(typeStr, "nondefaultopts")].(*Config)
	assert.Equal(t, r3.Endpoint, "localhost:4244")
	assert.Equal(t, *r3.FlowEncodingOptions.Traces.Encoding, "JSON")
	assert.Equal(t, *r3.FlowEncodingOptions.Traces.TopLevelKeys, false)
	assert.Equal(t, *r3.FlowEncodingOptions.Logs.LogPayloadAsBody, true)
}
