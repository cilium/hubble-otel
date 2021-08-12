package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	logsCollectorV1 "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonV1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsV1 "go.opentelemetry.io/proto/otlp/logs/v1"
	resourceV1 "go.opentelemetry.io/proto/otlp/resource/v1"

	"github.com/cilium/cilium/api/v1/observer"
)

type flags struct {
	address *string
	tls     *flagsTLS
}

type flagsTLS struct {
	enable, insecureSkipVerify *bool

	clientCertificate, clientKey, certificateAuthority *string
}

// TODO: add prometheus metircs for buffer size, throughput, errors, etc

func main() {
	flagsHubble := flags{
		address: flag.String("hubble.address", "localhost:4245", "connect to Hubble on this address"),
		tls: &flagsTLS{
			enable:               flag.Bool("hubble.tls.enable", false, "connect to Hubble using TLS"),
			insecureSkipVerify:   flag.Bool("hubble.tls.insecureSkipVerify", false, "disable TLS verification for Hubble"),
			clientCertificate:    flag.String("hubble.tls.clientCertificate", "", ""),
			clientKey:            flag.String("hubble.tls.clientKey", "", ""),
			certificateAuthority: flag.String("hubble.tls.certificateAuthority", "", ""),
		},
	}

	flagsOTLP := flags{
		address: flag.String("otlp.address", "", "connect to OTLP receiver on this address"),
		tls: &flagsTLS{
			enable:               flag.Bool("otlp.tls.enable", false, "connect to OTLP receiver using TLS"),
			insecureSkipVerify:   flag.Bool("otlp.tls.insecureSkipVerify", false, "disable TLS verification for OTLP receiver"),
			clientCertificate:    flag.String("otlp.tls.clientCertificate", "", ""),
			clientKey:            flag.String("otlp.tls.clientKey", "", ""),
			certificateAuthority: flag.String("otlp.tls.certificateAuthority", "", ""),
		},
	}

	logBufferSize := flag.Int("logBufferSize", 2048, "size of the buffer")

	flag.Parse()

	if err := run(flagsHubble, flagsOTLP, *logBufferSize); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func (f *flagsTLS) loadCredentials() (credentials.TransportCredentials, error) {
	config := &tls.Config{
		InsecureSkipVerify: *f.insecureSkipVerify,
	}

	if *f.clientCertificate != "" && *f.clientKey != "" {
		keyPair, err := tls.LoadX509KeyPair(*f.clientCertificate, *f.clientKey)
		if err != nil {
			return nil, fmt.Errorf("cannot parse client certificate/key pair: %w", err)
		}
		config.Certificates = []tls.Certificate{keyPair}
	} else {
		return nil, fmt.Errorf("cleint certificate/key pair must be specified when TLS is enabled")
	}

	if *f.certificateAuthority != "" {
		config.RootCAs = x509.NewCertPool()
		data, err := os.ReadFile(*f.certificateAuthority)
		if err != nil {
			return nil, fmt.Errorf("cannot open CA certificate %q: %w", *f.certificateAuthority, err)
		}
		if ok := config.RootCAs.AppendCertsFromPEM(data); !ok {
			return nil, fmt.Errorf("cannot parse CA certificate %q: invalid PEM", *f.certificateAuthority)
		}
	} else if !*f.insecureSkipVerify {
		return nil, fmt.Errorf("when verification is required CA certificate must be specified")
	}

	return credentials.NewTLS(config), nil
}

func dialContext(ctx context.Context, f *flags) (*grpc.ClientConn, error) {
	if !*f.tls.enable {
		return grpc.DialContext(ctx, *f.address, grpc.WithInsecure())
	}
	creds, err := f.tls.loadCredentials()
	if err != nil {
		return nil, err
	}
	return grpc.DialContext(ctx, *f.address, grpc.WithTransportCredentials(creds))
}

func run(hubbleFlags, otlpFlags flags, logBufferSize int) error {
	ctx := context.Background()

	hubbleConn, err := dialContext(ctx, &hubbleFlags)
	if err != nil {
		return fmt.Errorf("failed to connect to Hubble server: %w", err)
	}

	defer hubbleConn.Close()

	otlpConn, err := dialContext(ctx, &otlpFlags)
	if err != nil {
		return fmt.Errorf("failed to connect to OTLP receiver: %w", err)
	}

	defer otlpConn.Close()

	flows := make(chan *logsV1.ResourceLogs, logBufferSize)

	errs := make(chan error)

	go logSender(ctx, otlpConn, logBufferSize, flows, errs)

	go flowReciever(ctx, hubbleConn, flows, errs)

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errs:
			if err != nil {
				return err
			}
		}
	}
}

func flowReciever(ctx context.Context, hubbleConn *grpc.ClientConn, flows chan<- *logsV1.ResourceLogs, errs chan<- error) {
	flowObsever, err := observer.NewObserverClient(hubbleConn).
		GetFlows(ctx, &observer.GetFlowsRequest{Follow: true})
	if err != nil {
		errs <- err
		return
	}

	for {
		hubbleResp, err := flowObsever.Recv()
		switch err {
		case io.EOF, context.Canceled:
			return
		case nil:
		default:
			if status.Code(err) == codes.Canceled {
				return
			}
			errs <- err
			return
		}

		flow, err := newFlowLog(hubbleResp)
		if err != nil {
			errs <- err
			return
		}
		flows <- flow
	}
}

func logSender(ctx context.Context, otlpConn *grpc.ClientConn, logBufferSize int, flows <-chan *logsV1.ResourceLogs, errs chan<- error) {
	otlpLogs := logsCollectorV1.NewLogsServiceClient(otlpConn)

	for {
		logs := make([]*logsV1.ResourceLogs, logBufferSize)

		for i := range logs {
			logs[i] = <-flows
		}

		_, err := otlpLogs.Export(ctx, &logsCollectorV1.ExportLogsServiceRequest{ResourceLogs: logs})
		switch err {
		case io.EOF, context.Canceled:
			return
		case nil:
			fmt.Printf("wrote %d entries to the OTLP receiver\n", logBufferSize)
		default:
			if status.Code(err) == codes.Canceled {
				return
			}
			errs <- err
			return
		}
	}
}

const (
	keyPrefix = "io.cilium.otel."

	FlowLogAttributeLogKindVersion             = keyPrefix + "log_kind_version"
	FlowLogAttributeLogKindVersionFlowV1alpha1 = "flow/v1alpha1"
	FlowLogAttributeLogEncoding                = keyPrefix + "log_encoding"
	FlowLogAttributeLogEncodingJSON            = "JSON"

	FlowLogResourceCiliumClusterID = keyPrefix + "cluster_id"
	FlowLogResourceCiliumNodeName  = keyPrefix + "node_name"

	FlowLogBodyKeyFlowV1JSON = keyPrefix + "flow_v1_json"
)

func newFlowLog(hubbleResp *observer.GetFlowsResponse) (*logsV1.ResourceLogs, error) {
	flow := hubbleResp.GetFlow()

	// TODO: efficiency considerations
	// - store JSON as bytes or keep it as a string?
	// - can raw flow protobuf be extracted from the observer.GetFlowsResponse envelope? it maybe more efficient...
	// - what about ecoding to nested commonV1.KeyValueList structure instead of JSON?
	body, err := flow.MarshalJSON()
	if err != nil {
		return nil, err
	}

	return &logsV1.ResourceLogs{
		Resource: &resourceV1.Resource{
			Attributes: newStringAttributes(map[string]string{
				FlowLogResourceCiliumNodeName: flow.GetNodeName(),
			}),
		},
		InstrumentationLibraryLogs: []*logsV1.InstrumentationLibraryLogs{{
			Logs: []*logsV1.LogRecord{{
				TimeUnixNano: uint64(flow.GetTime().GetNanos()),
				Attributes: newStringAttributes(map[string]string{
					FlowLogAttributeLogKindVersion: FlowLogAttributeLogKindVersionFlowV1alpha1,
					FlowLogAttributeLogEncoding:    FlowLogAttributeLogEncodingJSON,
				}),
				Body: &commonV1.AnyValue{
					Value: &commonV1.AnyValue_KvlistValue{
						KvlistValue: &commonV1.KeyValueList{
							Values: []*commonV1.KeyValue{{
								Key: FlowLogBodyKeyFlowV1JSON,
								Value: &commonV1.AnyValue{
									Value: &commonV1.AnyValue_StringValue{
										StringValue: string(body),
									},
								},
							}},
						},
					},
				},
			}},
		}},
	}, nil
}

func newStringAttributes(attributes map[string]string) []*commonV1.KeyValue {
	results := []*commonV1.KeyValue{}
	for k, v := range attributes {
		results = append(results, &commonV1.KeyValue{
			Key: k,
			Value: &commonV1.AnyValue{
				Value: &commonV1.AnyValue_StringValue{
					StringValue: v,
				},
			},
		})
	}
	return results
}
