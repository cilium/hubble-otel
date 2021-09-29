// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package otlpgrpc

import (
	"context"

	"google.golang.org/grpc"

	"go.opentelemetry.io/collector/model/internal"
	otlpcollectormetrics "go.opentelemetry.io/collector/model/internal/data/protogen/collector/metrics/v1"
	"go.opentelemetry.io/collector/model/pdata"
)

// TODO: Consider to add `MetricsRequest`. If we add non pdata properties we can add them to the request.

// MetricsResponse represents the response for gRPC client/server.
type MetricsResponse struct {
	orig *otlpcollectormetrics.ExportMetricsServiceResponse
}

// NewMetricsResponse returns an empty MetricsResponse.
func NewMetricsResponse() MetricsResponse {
	return MetricsResponse{orig: &otlpcollectormetrics.ExportMetricsServiceResponse{}}
}

// MetricsClient is the client API for OTLP-GRPC Metrics service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type MetricsClient interface {
	// Export pdata.Metrics to the server.
	//
	// For performance reasons, it is recommended to keep this RPC
	// alive for the entire life of the application.
	Export(ctx context.Context, in pdata.Metrics, opts ...grpc.CallOption) (MetricsResponse, error)
}

type metricsClient struct {
	rawClient otlpcollectormetrics.MetricsServiceClient
}

// NewMetricsClient returns a new MetricsClient connected using the given connection.
func NewMetricsClient(cc *grpc.ClientConn) MetricsClient {
	return &metricsClient{rawClient: otlpcollectormetrics.NewMetricsServiceClient(cc)}
}

func (c *metricsClient) Export(ctx context.Context, in pdata.Metrics, opts ...grpc.CallOption) (MetricsResponse, error) {
	rsp, err := c.rawClient.Export(ctx, internal.MetricsToOtlp(in.InternalRep()), opts...)
	return MetricsResponse{orig: rsp}, err
}

// MetricsServer is the server API for OTLP gRPC MetricsService service.
type MetricsServer interface {
	// Export is called every time a new request is received.
	//
	// For performance reasons, it is recommended to keep this RPC
	// alive for the entire life of the application.
	Export(context.Context, pdata.Metrics) (MetricsResponse, error)
}

// RegisterMetricsServer registers the MetricsServer to the grpc.Server.
func RegisterMetricsServer(s *grpc.Server, srv MetricsServer) {
	otlpcollectormetrics.RegisterMetricsServiceServer(s, &rawMetricsServer{srv: srv})
}

type rawMetricsServer struct {
	srv MetricsServer
}

func (s rawMetricsServer) Export(ctx context.Context, request *otlpcollectormetrics.ExportMetricsServiceRequest) (*otlpcollectormetrics.ExportMetricsServiceResponse, error) {
	rsp, err := s.srv.Export(ctx, pdata.MetricsFromInternalRep(internal.MetricsFromOtlp(request)))
	return rsp.orig, err
}
