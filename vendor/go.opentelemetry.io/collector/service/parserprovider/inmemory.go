// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package parserprovider // import "go.opentelemetry.io/collector/service/parserprovider"

import (
	"context"
	"io"

	"go.opentelemetry.io/collector/config"
)

type inMemoryMapProvider struct {
	buf io.Reader
}

// NewInMemoryMapProvider returns a new MapProvider that reads the configuration, from the provided buffer, as YAML.
func NewInMemoryMapProvider(buf io.Reader) MapProvider {
	return &inMemoryMapProvider{buf: buf}
}

func (inp *inMemoryMapProvider) Get(context.Context) (*config.Map, error) {
	return config.NewMapFromBuffer(inp.buf)
}

func (inp *inMemoryMapProvider) Close(context.Context) error {
	return nil
}
