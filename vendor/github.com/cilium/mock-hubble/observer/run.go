// Copyright 2021 Authors of Hubble
// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package observer

import (
	"context"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/hubble/server"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// TLSPaths allows passing TLS certificate files to Run.
type TLSPaths struct {
	Certificate, Key, CertificateAuthority string
}

// Run sets up mock-hubble server in an opinionated way, it's very suitable for most use-cases.
func Run(ctx context.Context, log *logrus.Logger, dir, address string, rateAdjustment int, withTLSPath *TLSPaths, fatal chan<- error) {
	mockObeserver, err := New(log.WithField(logfields.LogSubsys, "mock-hubble-observer"),
		WithSampleDir(dir),
		WithRateAdjustment(int64(rateAdjustment)),
	)
	if err != nil {
		fatal <- err
		return
	}

	tlsOption := serveroption.WithInsecure()

	if withTLSPath != nil {
		serverConfigBuilder, err := certloader.NewWatchedServerConfig(log,
			[]string{withTLSPath.CertificateAuthority},
			withTLSPath.Certificate,
			withTLSPath.Key,
		)
		if err != nil {
			fatal <- err
			return
		}
		tlsOption = serveroption.WithServerTLS(serverConfigBuilder)
	}

	mockServer, err := server.NewServer(log.WithField(logfields.LogSubsys, "mock-hubble-server"),
		serveroption.WithTCPListener(address),
		tlsOption,
		serveroption.WithHealthService(),
		serveroption.WithObserverService(mockObeserver),
	)
	if err != nil {
		fatal <- err
		return
	}

	log.WithField("address", address).Info("Starting Hubble server")

	if err := mockServer.Serve(); err != nil {
		fatal <- err
		return
	}

	for {
		select {
		case <-ctx.Done():
			log.WithField("address", address).Info("Stopping Hubble server")
			mockServer.Stop()
			return
		}
	}
}
