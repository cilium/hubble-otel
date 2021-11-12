package common

import (
	"context"
	"fmt"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"

	flowV1 "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
)

type Converter interface {
	Convert(*observer.GetFlowsResponse) (protoreflect.Message, error)
	InclusionFilter() []*flowV1.FlowFilter
}

func RunConverter(ctx context.Context, hubbleConn *grpc.ClientConn, c Converter, flows chan<- protoreflect.Message, errs chan<- error, opts ...grpc.CallOption) {
	req := &observer.GetFlowsRequest{
		Follow:    true,
		Whitelist: c.InclusionFilter(),
	}
	flowObsever, err := observer.NewObserverClient(hubbleConn).
		GetFlows(ctx, req, opts...)
	if err != nil {
		errs <- fmt.Errorf("GetFlows failed: %w", err)
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
			errs <- fmt.Errorf("unexpected response from Hubble: %w", err)
			return
		}

		if hubbleResp.GetFlow() == nil {
			if lostEvents := hubbleResp.GetLostEvents(); lostEvents != nil {
				errs <- fmt.Errorf("observed Hubble lost events: %d", lostEvents.NumEventsLost)
			}
			continue
		}

		flow, err := c.Convert(hubbleResp)
		if err != nil {
			errs <- fmt.Errorf("converter failed: %w", err)
			return
		}
		flows <- flow
	}
}
