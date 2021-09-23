package receiver

import (
	"context"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/cilium/cilium/api/v1/observer"
)

type Converter interface {
	Convert(*observer.GetFlowsResponse) (protoreflect.Message, error)
}

func Run(ctx context.Context, hubbleConn *grpc.ClientConn, c Converter, flows chan<- protoreflect.Message, errs chan<- error) {
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

		flow, err := c.Convert(hubbleResp)
		if err != nil {
			errs <- err
			return
		}
		flows <- flow
	}
}
