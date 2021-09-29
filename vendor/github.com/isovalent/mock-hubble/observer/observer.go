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
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	observer "github.com/cilium/cilium/api/v1/observer"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/peer"
)

// Observer implement Hubble's ObserverServer
type Observer struct {
	log  logrus.FieldLogger
	opts Options

	// startTime is the time when this instance was started
	startTime time.Time
	// numObservedFlows counts how many flows have been observed
	numObservedFlows uint64
	// UnimplementedObserverServer is embedded for forward compatibility.
	observer.UnimplementedObserverServer
}

var _ observer.ObserverServer = &Observer{}

// New create and return a new Observer that can be used as a Hubble Observer service.
func New(log logrus.FieldLogger, options ...Option) (*Observer, error) {
	opts := Options{
		RateAdjustment: 0,
	}
	for _, opt := range options {
		if err := opt(&opts); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	startTime := time.Now()

	s := Observer{
		log:       log,
		opts:      opts,
		startTime: startTime,
	}
	return &s, nil
}

// GetFlows implements ObserverServer for the Observer struct.
func (s *Observer) GetFlows(req *observer.GetFlowsRequest, srv observer.Observer_GetFlowsServer) error {
	ctx := srv.Context()

	log := s.log.WithField("method", "GetFlows")
	if p, ok := peer.FromContext(ctx); ok {
		log = log.WithField("from", p.Addr.String())
	}
	log.Info("connected")
	defer log.Info("disconnected")

	sampler := &sampler{
		log:            log.WithField("component", "sampler"),
		dir:            s.opts.SampleDir,
		rateAdjustment: s.opts.RateAdjustment,
		startTime:      time.Now(),
	}

	if err := sampler.init(); err != nil {
		log.WithError(err).Info("initialising the sampler")
		return err
	}

	n := req.GetNumber()
	// NB: req.GetSince() is not needed for hubble-toolbox, so it's unimplemented

	if n > 0 {
		log.WithField("count", n).Debug("answering")
	}

	events := make(chan *observer.GetFlowsResponse)
	errs := make(chan error)

	go sampler.process(ctx, events, errs)

	respond := func() error {
		select {
		case rsp := <-events:
			if err := srv.Send(rsp); err != nil {
				return err
			}
			atomic.AddUint64(&s.numObservedFlows, 1)
		case <-ctx.Done():
			return errors.New("cancelled")
		case err := <-errs:
			if err == nil {
				// scanner masks EOF as nil, unmask it here
				// in order to distinguish from the general
				// non-errors cases of this function
				return io.EOF
			}
			return err
		}
		return nil
	}

	for i := uint64(0); i < n; i++ {
		if err := respond(); err != nil {
			return err
		}
	}

	if req.GetFollow() {
		log.Debug("follow")
		for {
			if err := respond(); err != nil {
				return err
			}
		}
	}

	return nil
}

// ServerStatus implements ObserverServer for the Observer struct.
func (s *Observer) ServerStatus(ctx context.Context, req *observer.ServerStatusRequest) (*observer.ServerStatusResponse, error) {
	log := s.log.WithField("method", "ServerStatus")
	if p, ok := peer.FromContext(ctx); ok {
		log = log.WithField("from", p.Addr.String())
	}
	log.Info("connected")

	return &observer.ServerStatusResponse{
		MaxFlows:  0,
		NumFlows:  0,
		SeenFlows: atomic.LoadUint64(&s.numObservedFlows),
		UptimeNs:  uint64(time.Since(s.startTime).Nanoseconds()),
	}, nil
}
