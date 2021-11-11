package receiver_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/hubble-otel/receiver"
	"github.com/cilium/hubble-otel/testutil"
)

const (
	hubbleAddress       = "localhost:4245"
	promReceiverAddress = "localhost:8888"
	promExporterAddress = "localhost:8889"

	metricsURL = "http://" + promExporterAddress + "/metrics"
)

func TestIntegration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fatal := make(chan error, 1)

	log := logrus.New()
	//log.SetLevel(logrus.DebugLevel)

	tlsPaths := &testutil.TLSPaths{
		Certificate:          "../testdata/certs/test-server.pem",
		Key:                  "../testdata/certs/test-server-key.pem",
		CertificateAuthority: "../testdata/certs/ca.pem",
	}

	go testutil.RunMockHubble(context.Background(), log, "../testdata/2021-10-04-sample-flows-istio-gke-l7", hubbleAddress, 100, tlsPaths, fatal)

	testutil.WaitForServer(ctx, t.Logf, hubbleAddress)

	go testutil.RunOpenTelemtryCollector(ctx, t, "testdata/collector-with-tls.yaml", fatal, receiver.NewFactory())

	go func() {
		for err := range fatal {
			fmt.Printf("fatal error in a goroutine: %v\n", err)
			cancel()
			return
		}
	}()

	testutil.WaitForServer(ctx, t.Logf, promExporterAddress)
	testutil.WaitForServer(ctx, t.Logf, promReceiverAddress)

	checkCollectorMetrics(ctx, t, metricsURL, 15000)
}

func checkCollectorMetrics(ctx context.Context, t *testing.T, metricsURL string, flowCount float64) {
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(2*time.Minute))
	defer cancel()

	/*
		   integration_test.go:55: metrics: map[
			   otelcol_exporter_send_failed_log_records:name:"otelcol_exporter_send_failed_log_records" help:"Number of log records in failed attempts to send to destination." type:COUNTER metric:<label:<name:"exporter" value:"logging" > label:<name:"service_instance_id" value:"a4ab75df-1d3d-462c-8ff5-d35f9cf0d2b4" > label:<name:"service_version" value:"latest" > counter:<value:0 > >
			   otelcol_exporter_send_failed_requests:name:"otelcol_exporter_send_failed_requests" help:"number of times exporters failed to send requests to the destination" type:COUNTER metric:<label:<name:"service_instance_id" value:"a4ab75df-1d3d-462c-8ff5-d35f9cf0d2b4" > label:<name:"service_version" value:"latest" > counter:<value:4 > >
			   otelcol_exporter_send_failed_spans:name:"otelcol_exporter_send_failed_spans" help:"Number of spans in failed attempts to send to destination." type:COUNTER metric:<label:<name:"exporter" value:"logging" > label:<name:"service_instance_id" value:"a4ab75df-1d3d-462c-8ff5-d35f9cf0d2b4" > label:<name:"service_version" value:"latest" > counter:<value:0 > >
			   otelcol_exporter_sent_log_records:name:"otelcol_exporter_sent_log_records" help:"Number of log record successfully sent to destination." type:COUNTER metric:<label:<name:"exporter" value:"logging" > label:<name:"service_instance_id" value:"a4ab75df-1d3d-462c-8ff5-d35f9cf0d2b4" > label:<name:"service_version" value:"latest" > counter:<value:8192 > >
			   otelcol_exporter_sent_spans:name:"otelcol_exporter_sent_spans" help:"Number of spans successfully sent to destination." type:COUNTER metric:<label:<name:"exporter" value:"logging" > label:<name:"service_instance_id" value:"a4ab75df-1d3d-462c-8ff5-d35f9cf0d2b4" > label:<name:"service_version" value:"latest" > counter:<value:8192 > >
			   otelcol_process_cpu_seconds:name:"otelcol_process_cpu_seconds" help:"Total CPU user and system time in seconds" type:GAUGE metric:<label:<name:"service_instance_id" value:"a4ab75df-1d3d-462c-8ff5-d35f9cf0d2b4" > label:<name:"service_version" value:"latest" > gauge:<value:34.69 > >
			   otelcol_process_memory_rss:name:"otelcol_process_memory_rss" help:"Total physical memory (resident set size)" type:GAUGE metric:<label:<name:"service_instance_id" value:"a4ab75df-1d3d-462c-8ff5-d35f9cf0d2b4" > label:<name:"service_version" value:"latest" > gauge:<value:2.78454272e+08 > >
			   otelcol_process_runtime_heap_alloc_bytes:name:"otelcol_process_runtime_heap_alloc_bytes" help:"Bytes of allocated heap objects (see 'go doc runtime.MemStats.HeapAlloc')" type:GAUGE metric:<label:<name:"service_instance_id" value:"a4ab75df-1d3d-462c-8ff5-d35f9cf0d2b4" > label:<name:"service_version" value:"latest" > gauge:<value:2.3910956e+08 > >
			   otelcol_process_runtime_total_alloc_bytes:name:"otelcol_process_runtime_total_alloc_bytes" help:"Cumulative bytes allocated for heap objects (see 'go doc runtime.MemStats.TotalAlloc')" type:GAUGE metric:<label:<name:"service_instance_id" value:"a4ab75df-1d3d-462c-8ff5-d35f9cf0d2b4" > label:<name:"service_version" value:"latest" > gauge:<value:4.638637384e+09 > >
			   otelcol_process_runtime_total_sys_memory_bytes:name:"otelcol_process_runtime_total_sys_memory_bytes" help:"Total bytes of memory obtained from the OS (see 'go doc runtime.MemStats.Sys')" type:GAUGE metric:<label:<name:"service_instance_id" value:"a4ab75df-1d3d-462c-8ff5-d35f9cf0d2b4" > label:<name:"service_version" value:"latest" > gauge:<value:3.3959636e+08 > >
			   otelcol_process_uptime:name:"otelcol_process_uptime" help:"Uptime of the process" type:COUNTER metric:<label:<name:"service_instance_id" value:"a4ab75df-1d3d-462c-8ff5-d35f9cf0d2b4" > label:<name:"service_version" value:"latest" > counter:<value:5.016992 > >
			   otelcol_processor_batch_batch_send_size:name:"otelcol_processor_batch_batch_send_size" help:"Number of units in the batch" type:HISTOGRAM metric:<label:<name:"processor" value:"batch" > label:<name:"service_instance_id" value:"a4ab75df-1d3d-462c-8ff5-d35f9cf0d2b4" > label:<name:"service_version" value:"latest" > histogram:<sample_count:8 sample_sum:16384 bucket:<cumulative_count:0 upper_bound:10 > bucket:<cumulative_count:0 upper_bound:25 > bucket:<cumulative_count:0 upper_bound:50 > bucket:<cumulative_count:0 upper_bound:75 > bucket:<cumulative_count:0 upper_bound:100 > bucket:<cumulative_count:0 upper_bound:250 > bucket:<cumulative_count:0 upper_bound:500 > bucket:<cumulative_count:0 upper_bound:750 > bucket:<cumulative_count:0 upper_bound:1000 > bucket:<cumulative_count:0 upper_bound:2000 > bucket:<cumulative_count:8 upper_bound:3000 > bucket:<cumulative_count:8 upper_bound:4000 > bucket:<cumulative_count:8 upper_bound:5000 > bucket:<cumulative_count:8 upper_bound:6000 > bucket:<cumulative_count:8 upper_bound:7000 > bucket:<cumulative_count:8 upper_bound:8000 > bucket:<cumulative_count:8 upper_bound:9000 > bucket:<cumulative_count:8 upper_bound:10000 > bucket:<cumulative_count:8 upper_bound:20000 > bucket:<cumulative_count:8 upper_bound:30000 > bucket:<cumulative_count:8 upper_bound:50000 > bucket:<cumulative_count:8 upper_bound:100000 > bucket:<cumulative_count:8 upper_bound:inf > > >  otelcol_processor_batch_timeout_trigger_send:name:"otelcol_processor_batch_timeout_trigger_send" help:"Number of times the batch was sent due to a timeout trigger" type:COUNTER metric:<label:<name:"processor" value:"batch" > label:<name:"service_instance_id" value:"a4ab75df-1d3d-462c-8ff5-d35f9cf0d2b4" > label:<name:"service_version" value:"latest" > counter:<value:8 > >  scrape_duration_seconds:name:"scrape_duration_seconds" help:"Duration of the scrape" type:GAUGE metric:<gauge:<value:0.005121258 > >  scrape_samples_post_metric_relabeling:name:"scrape_samples_post_metric_relabeling" help:"The number of samples remaining after metric relabeling was applied" type:GAUGE metric:<gauge:<value:37 > >  scrape_samples_scraped:name:"scrape_samples_scraped" help:"The number of samples the target exposed" type:GAUGE metric:<gauge:<value:37 > >  scrape_series_added:name:"scrape_series_added" help:"The approximate number of new series in this scrape" type:GAUGE metric:<gauge:<value:37 > >  up:name:"up" help:"The scraping was successful" type:GAUGE metric:<gauge:<value:1 > > ]
	*/

	// t.Logf("metrics: %v", mf)

	var failCountersErr, sentCountersErr error
	for {
		select {
		case <-time.After(50 * time.Millisecond):
			mf := testutil.GetMetricFamilies(ctx, t, metricsURL)

			failCountersErr = testutil.CheckCounterMetricIsZero(mf, "otelcol_exporter_send_failed_log_records", "otelcol_exporter_send_failed_spans")
			sentCountersErr = testutil.CheckCounterMetricIsGreaterThen(flowCount, mf, "otelcol_exporter_sent_log_records", "otelcol_exporter_sent_spans")
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
