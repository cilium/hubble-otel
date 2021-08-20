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
	logsV1 "go.opentelemetry.io/proto/otlp/logs/v1"

	"github.com/cilium/cilium/api/v1/observer"
	"github.com/isovalent/hubble-otel/converter"
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
	encodingFormat := flag.String("encodingFormat", converter.DefaultEncoding, fmt.Sprintf("encoding format (valid options: %v)", converter.EncodingFormats()))
	useAttributes := flag.Bool("useAttributes", false, "use attributes instead of body")

	flag.Parse()

	if err := run(flagsHubble, flagsOTLP, *logBufferSize, *encodingFormat, *useAttributes); err != nil {
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

func run(hubbleFlags, otlpFlags flags, logBufferSize int, encodingFormat string, useAttributes bool) error {
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

	go flowReciever(ctx, hubbleConn, encodingFormat, useAttributes, flows, errs)

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

func flowReciever(ctx context.Context, hubbleConn *grpc.ClientConn, encodingFormat string, useAttributes bool, flows chan<- *logsV1.ResourceLogs, errs chan<- error) {
	flowObsever, err := observer.NewObserverClient(hubbleConn).
		GetFlows(ctx, &observer.GetFlowsRequest{Follow: true})
	if err != nil {
		errs <- err
		return
	}

	c := converter.FlowConverter{
		Encoding:      encodingFormat,
		UseAttributes: useAttributes,
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

		flow, err := c.Convert(hubbleResp)
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
