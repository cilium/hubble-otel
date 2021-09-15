package traceconv

import (
	"fmt"
	"hash/fnv"
	"os"
	"time"

	badger "github.com/dgraph-io/badger/v3"
	"go.opentelemetry.io/otel/trace"

	"github.com/cilium/cilium/api/v1/flow"
)

type TraceCache struct {
	MaxTraceLength time.Duration

	badgerDB *badger.DB
}

func NewTraceCache(opt badger.Options) (*TraceCache, error) {
	db, err := badger.Open(opt)
	if err != nil {
		return nil, err
	}
	return &TraceCache{
		MaxTraceLength: 20 * time.Minute,
		badgerDB:       db,
	}, nil
}

func (tc *TraceCache) GetIDs(f *flow.Flow) (trace.TraceID, trace.SpanID, error) {
	traceID := trace.TraceID{}
	spanID := trace.SpanID{}

	err := tc.badgerDB.Update(func(txn *badger.Txn) error {
		kt := getFlowKeyPrefices(f)
		if !kt.isValid() {
			return nil
		}

		flowData, err := f.MarshalJSON()
		if err != nil {
			return fmt.Errorf("unable to serialise flow: %w", err)
		}

		hash := fnv.New64a()

		_, _ = hash.Write(flowData) // this FNV generator never returns errors

		_ = hash.Sum(spanID[:0]) // aways generate new span ID
		fetchedTraceID, err := kt.fetchTraceID(txn)
		if err != nil {
			return fmt.Errorf("unable to get span/trace ID: %w", err)
		}
		if fetchedTraceID.IsValid() {
			copy(traceID[:], fetchedTraceID[:])
		} else {
			_ = hash.Sum(traceID[:0]) // trace ID is same as the one of the first span
			data := map[string][]byte{
				traceIDKey(kt.primary()):  traceID[:],
				flowDataKey(kt.primary()): flowData,
			}
			if err := tc.storeKeys(txn, data); err != nil {
				return fmt.Errorf("unable to store generated new trace ID: %w", err)
			}
		}
		return nil
	})

	if err != nil {
		return traceID, spanID, err
	}
	return traceID, spanID, nil
}

func (tc *TraceCache) Close() error {
	return tc.badgerDB.Close()
}

func (tc *TraceCache) Delete() {
	_ = tc.Close()
	os.RemoveAll(tc.badgerDB.Opts().Dir)
}

type keyTuple [2]string

func (kt keyTuple) primary() string { return kt[0] }

func (kt keyTuple) isValid() bool { return kt != (keyTuple{}) }

func (kt keyTuple) fetchTraceID(txn *badger.Txn) (trace.TraceID, error) {
	traceID := trace.TraceID{}
	for _, keyPrefix := range kt {
		item, err := txn.Get([]byte(traceIDKey(keyPrefix)))
		switch err {
		case nil:
			err := item.Value(func(val []byte) error {
				if len(val) != len(traceID) {
					return fmt.Errorf("stored trace ID is invlaid")
				}
				copy(traceID[:], val)
				return nil
			})
			if err != nil {
				return trace.TraceID{}, err
			}
		case badger.ErrKeyNotFound:
			continue
		default:
			return trace.TraceID{}, fmt.Errorf("unexpected error getting trace ID: %w", err)
		}
	}
	return traceID, nil
}

func getFlowKeyPrefices(f *flow.Flow) keyTuple {
	var src, dst string

	if ip := f.GetIP(); ip != nil {
		switch ip.GetIpVersion() {
		case flow.IPVersion_IPv4:
			src = ip.Source
			dst = ip.Destination
		case flow.IPVersion_IPv6:
			src = "[" + ip.Source + "]"
			dst = "[" + ip.Destination + "]"
		}
	}

	haveL4 := false
	if tcp := f.L4.GetTCP(); tcp != nil {
		src += fmt.Sprintf(":%d", tcp.SourcePort)
		dst += fmt.Sprintf(":%d", tcp.DestinationPort)
		haveL4 = true
	}
	if udp := f.L4.GetUDP(); udp != nil {
		src += fmt.Sprintf(":%d", udp.SourcePort)
		dst += fmt.Sprintf(":%d", udp.DestinationPort)
		haveL4 = true
	}
	if icmp := f.L4.GetICMPv4(); icmp != nil {
		src += fmt.Sprintf("/%d", icmp.Type)
		haveL4 = true
	}
	if icmp := f.L4.GetICMPv6(); icmp != nil {
		src += fmt.Sprintf("/%d", icmp.Type)
		haveL4 = true
	}

	if !haveL4 || src == "" || dst == "" {
		return keyTuple{}
	}
	return keyTuple{src + "<=>" + dst, dst + "<=>" + src}
}

func (tc *TraceCache) storeKeys(txn *badger.Txn, data map[string][]byte) error {
	for k, v := range data {
		entry := badger.NewEntry([]byte(k), v).WithTTL(tc.MaxTraceLength)
		if err := txn.SetEntry(entry); err != nil {
			return fmt.Errorf("unable to store %q: %w", k, err)
		}
	}
	return nil
}

func flowDataKey(k string) string {
	return k + "/flowdData"
}

func traceIDKey(k string) string {
	return k + "/traceID"
}
