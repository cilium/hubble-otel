package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/isovalent/hubble-otel/common"
	"github.com/isovalent/hubble-otel/logconv"
	"github.com/isovalent/hubble-otel/logproc"
	"github.com/isovalent/hubble-otel/receiver"
	"github.com/isovalent/hubble-otel/sender"
	"github.com/isovalent/hubble-otel/traceconv"
	"github.com/isovalent/hubble-otel/traceproc"
)

type flags struct {
	address *string
	tls     *flagsTLS
}

type flagsTLS struct {
	enable, insecureSkipVerify *bool

	clientCertificate, clientKey, certificateAuthority *string
}

// TODO: add prometheus metircs for buffer size, throughput, errors, badger ops etc

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

	otlpHeaders := flag.String("otlp.headers", "", "specify OTLP headers to use as a JSON object")

	bufferSize := flag.Int("bufferSize", 2048, "number of logs/spans to buffer before exporting")
	encodingFormat := flag.String("encodingFormat", common.DefaultEncoding, fmt.Sprintf("encoding format (valid options: %v)", common.EncodingFormats()))
	useLogAttributes := flag.Bool("useLogAttributes", true, "use attributes instead of body")
	exportLogs := flag.Bool("exportLogs", true, "export flows as logs")
	exportTraces := flag.Bool("exportTraces", true, "export flows as traces")

	flag.Parse()

	otlpHeadersObj := map[string]string{}

	if err := json.Unmarshal([]byte(*otlpHeaders), &otlpHeadersObj); err != nil {
		fmt.Printf("cannot parse OTLP headers: %s\n", err)
	}

	if err := run(flagsHubble, flagsOTLP, otlpHeadersObj, *exportLogs, *exportTraces, *bufferSize, *encodingFormat, *useLogAttributes); err != nil {
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
	}
	// else {
	// 	return nil, fmt.Errorf("cleint certificate/key pair must be specified when TLS is enabled")
	// }

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

func run(hubbleFlags, otlpFlags flags, otlpHeaders map[string]string, exportLogs, exportTraces bool, bufferSize int, encodingFormat string, useLogAttributes bool) error {
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

	errs := make(chan error)

	if exportLogs {
		flowsToLogs := make(chan protoreflect.Message, bufferSize)

		logConverter := logconv.NewFlowConverter(encodingFormat, useLogAttributes)
		go receiver.Run(ctx, hubbleConn, logConverter, flowsToLogs, errs)

		exporter := logproc.NewBufferedLogExporter(otlpConn, bufferSize, otlpHeaders)
		go sender.Run(ctx, exporter, flowsToLogs, errs)
	}

	if exportTraces {
		spanDB, err := os.MkdirTemp("", "hubble-otel-trace-cache-") // TODO: allow user to pass dir name for persistence
		if err != nil {
			return fmt.Errorf("failed to create temporary directory for span database: %w", err)
		}

		flowsToTraces := make(chan protoreflect.Message, bufferSize)

		traceConverter, err := traceconv.NewFlowConverter(encodingFormat, spanDB)
		if err != nil {
			return fmt.Errorf("failed to create trace converter: %w", err)
		}
		// defer traceConverter.DeleteCache() // TODO: make this optional when persistence is enabled

		go receiver.Run(ctx, hubbleConn, traceConverter, flowsToTraces, errs)

		exporter := traceproc.NewBufferedTraceExporter(otlpConn, bufferSize, otlpHeaders)
		go sender.Run(ctx, exporter, flowsToTraces, errs)
	}

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
