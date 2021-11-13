package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/cilium/hubble-otel/common"
	"github.com/cilium/hubble-otel/logs"
	"github.com/cilium/hubble-otel/trace"
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
	fallbackServiceNamePrefix := flag.String("fallbackServiceNamePrefix", common.OTelAttrServiceNameDefaultPrefix, "fallback value to use for unknown 'service.name'")

	exportLogs := flag.Bool("logs.export", true, "export flows as logs")
	logsEncodingOptions := &common.EncodingOptions{
		Encoding:         flag.String("logs.format", common.DefaultLogEncoding, fmt.Sprintf("encoding format (valid options: %v)", common.EncodingFormatsForLogs())),
		LogPayloadAsBody: flag.Bool("logs.payloadAsBody", false, "use log body to store flow data instead of attributes"),
		TopLevelKeys:     flag.Bool("logs.useTopLevelKeys", false, "reduce nesting when storing flows as attributes"),
		LabelsAsMaps:     flag.Bool("logs.labelsAsMaps", false, "convert source/destination labels from arrays to maps"),
		HeadersAsMaps:    flag.Bool("logs.headersAsMaps", false, "convert HTTP headers from arrays to maps"),
	}

	exportTraces := flag.Bool("trace.export", true, "export flows as traces")
	traceEncodingOptions := &common.EncodingOptions{
		Encoding:      flag.String("trace.format", common.DefaultTraceEncoding, fmt.Sprintf("encoding format (valid options: %v)", common.EncodingFormatsForTraces())),
		TopLevelKeys:  flag.Bool("trace.useTopLevelKeys", false, "reduce nesting when storing flows as attributes"),
		LabelsAsMaps:  flag.Bool("trace.labelsAsMaps", false, "convert source/destination labels from arrays to maps"),
		HeadersAsMaps: flag.Bool("trace.headersAsMaps", false, "convert HTTP headers from arrays to maps"),
	}
	traceCacheWindow := flag.Duration("trace.cacheWindow", trace.DefaultTraceCacheWindow, "max lenght of cache window for trace IDs")
	parseTraceHeaders := flag.Bool("trace.parseHeaders", true, "weather to parse common HTTP trace headers")

	debug := flag.Bool("debug", false, "enable debug logs")

	flag.Parse()

	log := logrus.New()
	log.Formatter = &logrus.JSONFormatter{}
	if *debug {
		log.SetLevel(logrus.DebugLevel)
	} else {
		log.SetLevel(logrus.InfoLevel)
	}

	otlpHeadersObj := map[string]string{}

	if *otlpHeaders != "" {
		if err := json.Unmarshal([]byte(*otlpHeaders), &otlpHeadersObj); err != nil {
			log.Errorf("cannot parse OTLP headers: %s\n", err)
			os.Exit(2)
		}
	}

	if err := logsEncodingOptions.ValidForLogs(); err != nil {
		log.Errorf("logs encoding options are invalid: %s\n", err)
		os.Exit(2)
	}

	if err := traceEncodingOptions.ValidForTraces(); err != nil {
		log.Errorf("trace encoding options are invalid: %s\n", err)
		os.Exit(2)
	}

	if err := run(
		log,
		flagsHubble, flagsOTLP,
		otlpHeadersObj,
		*exportLogs, *exportTraces,
		*bufferSize,
		*fallbackServiceNamePrefix,
		logsEncodingOptions, traceEncodingOptions,
		*traceCacheWindow,
		*parseTraceHeaders,
	); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}

func (f *flagsTLS) loadCredentials(log *logrus.Logger) (credentials.TransportCredentials, error) {
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
		log.Warn("TLS authentication is disabled as client certificate/key pair wasn't specified")
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

func dialContext(ctx context.Context, log *logrus.Logger, f *flags) (*grpc.ClientConn, error) {
	if !*f.tls.enable {
		return grpc.DialContext(ctx, *f.address, grpc.WithInsecure())
	}
	creds, err := f.tls.loadCredentials(log)
	if err != nil {
		return nil, err
	}
	return grpc.DialContext(ctx, *f.address, grpc.WithTransportCredentials(creds))
}

func run(
	log *logrus.Logger,
	hubbleFlags, otlpFlags flags,
	otlpHeaders map[string]string,
	exportLogs, exportTraces bool,
	bufferSize int,
	fallbackServiceNamePrefix string,
	logsEncodingOptions, traceEncodingOptions *common.EncodingOptions,
	traceCacheWindow time.Duration,
	parseTraceHeaders bool,
) error {
	ctx := context.Background()

	hubbleConn, err := dialContext(ctx, log, &hubbleFlags)
	if err != nil {
		return fmt.Errorf("failed to connect to Hubble server: %w", err)
	}

	defer hubbleConn.Close()

	otlpConn, err := dialContext(ctx, log, &otlpFlags)
	if err != nil {
		return fmt.Errorf("failed to connect to OTLP receiver: %w", err)
	}

	defer otlpConn.Close()

	errs := make(chan error)

	if exportLogs {
		flowsToLogs := make(chan protoreflect.Message, bufferSize)

		converter := logs.NewFlowConverter(log, logsEncodingOptions, &common.IncludeFlowTypes{}, fallbackServiceNamePrefix)
		go common.RunConverter(ctx, hubbleConn, converter, flowsToLogs, errs)

		exporter := logs.NewBufferedLogExporter(otlpConn, bufferSize, otlpHeaders)
		go common.RunExporter(ctx, log, exporter, flowsToLogs, errs)
	}

	if exportTraces {
		spanDB, err := os.MkdirTemp("", "hubble-otel-trace-cache-") // TODO: allow user to pass dir name for persistence
		if err != nil {
			return fmt.Errorf("failed to create temporary directory for span database: %w", err)
		}

		flowsToTraces := make(chan protoreflect.Message, bufferSize)

		converter, err := trace.NewFlowConverter(log, spanDB, traceEncodingOptions, &common.IncludeFlowTypes{}, fallbackServiceNamePrefix, traceCacheWindow, parseTraceHeaders)
		if err != nil {
			return fmt.Errorf("failed to create trace converter: %w", err)
		}
		// defer converter.DeleteCache() // TODO: make this optional when persistence is enabled

		go common.RunConverter(ctx, hubbleConn, converter, flowsToTraces, errs)

		exporter := trace.NewBufferedTraceExporter(otlpConn, bufferSize, otlpHeaders)
		go common.RunExporter(ctx, log, exporter, flowsToTraces, errs)
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
