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
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/ulikunitz/xz"

	"github.com/cilium/cilium/api/v1/flow"
	observer "github.com/cilium/cilium/api/v1/observer"
)

type sampler struct {
	scanner        *bufio.Scanner
	firstTimestamp *time.Time

	startTime      time.Time
	dir            string
	rateAdjustment int64

	log logrus.FieldLogger
}

func (s *sampler) init() error {
	files, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}

	dataReaders := []io.Reader{}

	for _, f := range files {
		name := f.Name()
		if f.IsDir() {
			continue
		}

		f, err := os.Open(filepath.Join(s.dir, name))
		if err != nil {
			return err
		}

		if strings.HasSuffix(name, ".json") {
			dataReaders = append(dataReaders, f)
		}
		if strings.HasSuffix(name, ".json.xz") {
			r, err := xz.NewReader(f)
			if err != nil {
				return err
			}
			dataReaders = append(dataReaders, r)
		}
		if strings.HasSuffix(name, ".json.bz2") {
			dataReaders = append(dataReaders, bzip2.NewReader(f))
		}
		if strings.HasSuffix(name, ".json.gz") {
			r, err := gzip.NewReader(f)
			if err != nil {
				return err
			}
			dataReaders = append(dataReaders, r)
		}
	}

	if len(dataReaders) == 0 {
		return fmt.Errorf("no flow files found in %q with extensions '.json', '.json.(xz|bz2|gz)'", s.dir)
	}

	s.log.WithField("files", len(dataReaders)).Info("opened all JSON streams")

	s.scanner = bufio.NewScanner(io.MultiReader(dataReaders...))

	return nil
}
func (s *sampler) offsetTime(f *flow.Flow) {
	timestamp := f.Time.AsTime()
	if s.firstTimestamp == nil {
		s.firstTimestamp = &timestamp
		s.log.WithField("firstTimestamp", timestamp).Info("set initial timestamp to calculate offsets")
	}

	offsetBy := timestamp.Sub(*s.firstTimestamp)
	switch adj := s.rateAdjustment; {
	case adj < 0:
		offsetBy = time.Duration(offsetBy.Nanoseconds() * (adj * -1))
	case adj > 0:
		offsetBy = time.Duration(offsetBy.Nanoseconds() / adj)
	}

	timestampWithOffset := s.startTime.Add(offsetBy)

	f.Time.Seconds = int64(timestampWithOffset.Unix())
	f.Time.Nanos = int32(timestampWithOffset.Nanosecond())
}

func (s *sampler) process(ctx context.Context, events chan<- *observer.GetFlowsResponse, errs chan<- error) {
	for s.scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
			f := &flow.Flow{}
			var obj struct {
				Flow *flow.Flow `json:"flow"`
			}
			obj.Flow = f
			data := s.scanner.Bytes()
			if err := json.Unmarshal(data, &obj); err == nil {
				s.log.WithField("data", string(data)).Debug("parsing flow data")
				if f == nil {
					continue
				}

				s.offsetTime(f)
				time.Sleep(time.Until(f.Time.AsTime()))

				events <- &observer.GetFlowsResponse{
					NodeName: f.GetNodeName(),
					Time:     f.GetTime(),
					ResponseTypes: &observer.GetFlowsResponse_Flow{
						Flow: f,
					},
				}
			} else {
				s.log.WithError(err).Info("parsing flow data")
			}
		}
	}
	if err := s.scanner.Err(); err != nil {
		errs <- fmt.Errorf("reading sample data: %w", err)
		return
	}
	s.log.Info("no more sample data")
	errs <- nil
}
