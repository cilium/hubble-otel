package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/hubble-otel/common"
	"github.com/cilium/hubble-otel/testutil"
)

const (
	hubbleAddress       = "localhost:4245"
	colletorAddressGRPC = "localhost:55690"
	promReceiverAddress = "localhost:8888"
	promExporterAddress = "localhost:8889"

	metricsURL = "http://" + promExporterAddress + "/metrics"
)

func TestBasicIntegrationWithTLS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_false, _true := testutil.BoolValueRefs()

	newString := func(s string) *string { return &s }

	fatal := make(chan error, 1)

	go testutil.RunOpenTelemtryCollector(ctx, t, "testdata/collector-with-tls.yaml", fatal)

	log := logrus.New()
	//log.SetLevel(logrus.DebugLevel)

	tlsPaths := &testutil.TLSPaths{
		Certificate:          "testdata/certs/test-server.pem",
		Key:                  "testdata/certs/test-server-key.pem",
		CertificateAuthority: "testdata/certs/ca.pem",
	}

	go testutil.RunMockHubble(ctx, log, "testdata/2021-10-04-sample-flows-istio-gke-l7", hubbleAddress, 100, tlsPaths, fatal)

	go func() {
		for err := range fatal {
			fmt.Printf("fatal error in a goroutine: %v\n", err)
			cancel()
			return
		}
	}()

	commonFlagsTLS := &flagsTLS{
		enable:               _true,
		insecureSkipVerify:   _false,
		clientCertificate:    newString("testdata/certs/test-client.pem"),
		clientKey:            newString("testdata/certs/test-client-key.pem"),
		certificateAuthority: newString("testdata/certs/ca.pem"),
	}

	flagsHubble := flags{
		address: new(string),
		tls:     commonFlagsTLS,
	}

	*flagsHubble.address = hubbleAddress

	flagsOTLP := flags{
		address: new(string),
		tls:     commonFlagsTLS,
	}

	*flagsOTLP.address = colletorAddressGRPC

	testutil.WaitForServer(ctx, t.Logf, colletorAddressGRPC)
	testutil.WaitForServer(ctx, t.Logf, hubbleAddress)
	testutil.WaitForServer(ctx, t.Logf, promExporterAddress)
	testutil.WaitForServer(ctx, t.Logf, promReceiverAddress)

	_ = testutil.GetMetricFamilies(ctx, t, metricsURL)

	modes := map[string][]*common.EncodingOptions{
		// test option combinations that relevant to particular encoding
		common.EncodingJSON: {
			{TopLevelKeys: _false, LabelsAsMaps: _false, HeadersAsMaps: _false, LogPayloadAsBody: _false},
			{TopLevelKeys: _false, LabelsAsMaps: _false, HeadersAsMaps: _false, LogPayloadAsBody: _true},
		},

		common.EncodingJSONBASE64: {
			{TopLevelKeys: _false, LabelsAsMaps: _false, HeadersAsMaps: _false, LogPayloadAsBody: _false},
		},

		common.EncodingFlatStringMap: {
			{TopLevelKeys: _false, LabelsAsMaps: _false, HeadersAsMaps: _false, LogPayloadAsBody: _false},
			{TopLevelKeys: _false, LabelsAsMaps: _false, HeadersAsMaps: _false, LogPayloadAsBody: _true},
			{TopLevelKeys: _true, LabelsAsMaps: _false, HeadersAsMaps: _false, LogPayloadAsBody: _false},
			{TopLevelKeys: _true, LabelsAsMaps: _true, HeadersAsMaps: _true, LogPayloadAsBody: _false},
		},
		common.EncodingSemiFlatTypedMap: {
			{TopLevelKeys: _false, LabelsAsMaps: _false, HeadersAsMaps: _false, LogPayloadAsBody: _false},
			{TopLevelKeys: _false, LabelsAsMaps: _false, HeadersAsMaps: _false, LogPayloadAsBody: _true},
			{TopLevelKeys: _true, LabelsAsMaps: _false, HeadersAsMaps: _false, LogPayloadAsBody: _false},
			{TopLevelKeys: _true, LabelsAsMaps: _true, HeadersAsMaps: _true, LogPayloadAsBody: _false},
		},
		common.EncodingTypedMap: {
			{TopLevelKeys: _false, LabelsAsMaps: _false, HeadersAsMaps: _false, LogPayloadAsBody: _false},
			{TopLevelKeys: _false, LabelsAsMaps: _false, HeadersAsMaps: _false, LogPayloadAsBody: _true},
			{TopLevelKeys: _false, LabelsAsMaps: _true, HeadersAsMaps: _true, LogPayloadAsBody: _false},
		},
	}

	for k := range modes {
		for i := range modes[k] {
			options := modes[k][i]
			options.Encoding = &k

			t.Run(options.EncodingFormat()+":"+options.String(), func(t *testing.T) {
				if err := run(log, flagsHubble, flagsOTLP, nil, true, true, 10, common.OTelAttrServiceNameDefaultPrefix, options, options, 0, true); err != nil {
					if testutil.IsEOF(err) {
						// if sample a set contains 20000 flows, collector usually record between 17000 and 20000 for each iteration,
						// 75% seems like a good approximation for the purpose of this test
						checkCollectorMetrics(ctx, t, metricsURL, 40000.0*0.75, i)
						return
					}
					t.Fatal(err)
				}
			})
		}
	}
}

func checkCollectorMetrics(ctx context.Context, t *testing.T, metricsURL string, flowCount float64, iteration int) {
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(2*time.Minute))
	defer cancel()

	/*
		main_test.go:78: metrics: map[
			   otelcol_exporter_send_failed_log_records:name:"otelcol_exporter_send_failed_log_records" help:"Number of log records in failed attempts to send to destination." type:COUNTER metric:<label:<name:"exporter" value:"logging" > label:<name:"service_instance_id" value:"a9ca422c-ca34-4113-a6b0-57225bdb48a4" > counter:<value:0 > >
			   otelcol_exporter_send_failed_metric_points:name:"otelcol_exporter_send_failed_metric_points" help:"Number of metric points in failed attempts to send to destination." type:COUNTER metric:<label:<name:"exporter" value:"prometheus" > label:<name:"service_instance_id" value:"a9ca422c-ca34-4113-a6b0-57225bdb48a4" > counter:<value:0 > >
			   otelcol_exporter_sent_log_records:name:"otelcol_exporter_sent_log_records" help:"Number of log record successfully sent to destination." type:COUNTER metric:<label:<name:"exporter" value:"logging" > label:<name:"service_instance_id" value:"a9ca422c-ca34-4113-a6b0-57225bdb48a4" > counter:<value:19360 > >
			   otelcol_exporter_sent_metric_points:name:"otelcol_exporter_sent_metric_points" help:"Number of metric points successfully sent to destination." type:COUNTER metric:<label:<name:"exporter" value:"prometheus" > label:<name:"service_instance_id" value:"a9ca422c-ca34-4113-a6b0-57225bdb48a4" > counter:<value:1504 > >
			   otelcol_process_cpu_seconds:name:"otelcol_process_cpu_seconds" help:"Total CPU user and system time in seconds" type:GAUGE metric:<label:<name:"service_instance_id" value:"a9ca422c-ca34-4113-a6b0-57225bdb48a4" > gauge:<value:15.190000000000001 > >
			   otelcol_process_memory_rss:name:"otelcol_process_memory_rss" help:"Total physical memory (resident set size)" type:GAUGE metric:<label:<name:"service_instance_id" value:"a9ca422c-ca34-4113-a6b0-57225bdb48a4" > gauge:<value:6.3336448e+07 > >
			   otelcol_process_runtime_heap_alloc_bytes:name:"otelcol_process_runtime_heap_alloc_bytes" help:"Bytes of allocated heap objects (see 'go doc runtime.MemStats.HeapAlloc')" type:GAUGE metric:<label:<name:"service_instance_id" value:"a9ca422c-ca34-4113-a6b0-57225bdb48a4" > gauge:<value:1.0254496e+07 > >
			   otelcol_process_runtime_total_alloc_bytes:name:"otelcol_process_runtime_total_alloc_bytes" help:"Cumulative bytes allocated for heap objects (see 'go doc runtime.MemStats.TotalAlloc')" type:GAUGE metric:<label:<name:"service_instance_id" value:"a9ca422c-ca34-4113-a6b0-57225bdb48a4" > gauge:<value:1.320209472e+09 > >
			   otelcol_process_runtime_total_sys_memory_bytes:name:"otelcol_process_runtime_total_sys_memory_bytes" help:"Total bytes of memory obtained from the OS (see 'go doc runtime.MemStats.Sys')" type:GAUGE metric:<label:<name:"service_instance_id" value:"a9ca422c-ca34-4113-a6b0-57225bdb48a4" > gauge:<value:7.8201864e+07 > >
			   otelcol_process_uptime:name:"otelcol_process_uptime" help:"Uptime of the process" type:COUNTER metric:<label:<name:"service_instance_id" value:"a9ca422c-ca34-4113-a6b0-57225bdb48a4" > counter:<value:20.003828 > >
			   otelcol_processor_batch_batch_send_size:name:"otelcol_processor_batch_batch_send_size" help:"Number of units in the batch" type:HISTOGRAM metric:<label:<name:"processor" value:"batch" > label:<name:"service_instance_id" value:"a9ca422c-ca34-4113-a6b0-57225bdb48a4" > histogram:<sample_count:42 sample_sum:19810 bucket:<cumulative_count:0 upper_bound:10 > bucket:<cumulative_count:0 upper_bound:25 > bucket:<cumulative_count:0 upper_bound:50 > bucket:<cumulative_count:0 upper_bound:75 > bucket:<cumulative_count:0 upper_bound:100 > bucket:<cumulative_count:0 upper_bound:250 > bucket:<cumulative_count:21 upper_bound:500 > bucket:<cumulative_count:42 upper_bound:750 > bucket:<cumulative_count:42 upper_bound:1000 > bucket:<cumulative_count:42 upper_bound:2000 > bucket:<cumulative_count:42 upper_bound:3000 > bucket:<cumulative_count:42 upper_bound:4000 > bucket:<cumulative_count:42 upper_bound:5000 > bucket:<cumulative_count:42 upper_bound:6000 > bucket:<cumulative_count:42 upper_bound:7000 > bucket:<cumulative_count:42 upper_bound:8000 > bucket:<cumulative_count:42 upper_bound:9000 > bucket:<cumulative_count:42 upper_bound:10000 > bucket:<cumulative_count:42 upper_bound:20000 > bucket:<cumulative_count:42 upper_bound:30000 > bucket:<cumulative_count:42 upper_bound:50000 > bucket:<cumulative_count:42 upper_bound:100000 > bucket:<cumulative_count:42 upper_bound:inf > > >
			   otelcol_processor_batch_timeout_trigger_send:name:"otelcol_processor_batch_timeout_trigger_send" help:"Number of times the batch was sent due to a timeout trigger" type:COUNTER metric:<label:<name:"processor" value:"batch" > label:<name:"service_instance_id" value:"a9ca422c-ca34-4113-a6b0-57225bdb48a4" > counter:<value:42 > >
			   otelcol_receiver_accepted_log_records:name:"otelcol_receiver_accepted_log_records" help:"Number of log records successfully pushed into the pipeline." type:COUNTER metric:<label:<name:"receiver" value:"otlp" > label:<name:"service_instance_id" value:"a9ca422c-ca34-4113-a6b0-57225bdb48a4" > label:<name:"transport" value:"grpc" > counter:<value:19820 > >
			   otelcol_receiver_accepted_metric_points:name:"otelcol_receiver_accepted_metric_points" help:"Number of metric points successfully pushed into the pipeline." type:COUNTER metric:<label:<name:"receiver" value:"prometheus" > label:<name:"service_instance_id" value:"a9ca422c-ca34-4113-a6b0-57225bdb48a4" > label:<name:"transport" value:"http" > counter:<value:752 > >
			   otelcol_receiver_refused_log_records:name:"otelcol_receiver_refused_log_records" help:"Number of log records that could not be pushed into the pipeline." type:COUNTER metric:<label:<name:"receiver" value:"otlp" > label:<name:"service_instance_id" value:"a9ca422c-ca34-4113-a6b0-57225bdb48a4" > label:<name:"transport" value:"grpc" > counter:<value:0 > >
			   otelcol_receiver_refused_metric_points:name:"otelcol_receiver_refused_metric_points" help:"Number of metric points that could not be pushed into the pipeline." type:COUNTER metric:<label:<name:"receiver" value:"prometheus" > label:<name:"service_instance_id" value:"a9ca422c-ca34-4113-a6b0-57225bdb48a4" > label:<name:"transport" value:"http" > counter:<value:0 > >
			   scrape_duration_seconds:name:"scrape_duration_seconds" help:"Duration of the scrape" type:GAUGE metric:<gauge:<value:0.00229239 > >
			   scrape_samples_post_metric_relabeling:name:"scrape_samples_post_metric_relabeling" help:"The number of samples remaining after metric relabeling was applied" type:GAUGE metric:<gauge:<value:40 > >
			   scrape_samples_scraped:name:"scrape_samples_scraped" help:"The number of samples the target exposed" type:GAUGE metric:<gauge:<value:40 > >
			   scrape_series_added:name:"scrape_series_added" help:"The approximate number of new series in this scrape" type:GAUGE metric:<gauge:<value:40 > >
			   up:name:"up" help:"The scraping was successful" type:GAUGE metric:<gauge:<value:1 > >
		]
	*/

	// t.Logf("metrics: %v", mf)

	var failCountersErr, sentCountersErr error
	for {
		select {
		case <-time.After(50 * time.Millisecond):
			mf := testutil.GetMetricFamilies(ctx, t, metricsURL)

			failCountersErr = testutil.CheckCounterMetricIsZero(mf, "otelcol_exporter_send_failed_log_records", "otelcol_receiver_refused_log_records", "otelcol_exporter_send_failed_spans", "otelcol_receiver_refused_spans")
			sentCountersErr = testutil.CheckCounterMetricIsGreaterThen(flowCount*float64(iteration+1), mf, "otelcol_exporter_sent_log_records", "otelcol_receiver_accepted_log_records", "otelcol_exporter_sent_spans", "otelcol_receiver_accepted_spans")
			if failCountersErr == nil && sentCountersErr == nil {
				return
			}
		case <-ctx.Done():
			if failCountersErr != nil {
				t.Error(failCountersErr)
			}
			if sentCountersErr != nil {
				t.Error(sentCountersErr)
			}
		}
	}
}
