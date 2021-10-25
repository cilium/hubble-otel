package common

import (
	"context"
	"io"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type Exporter interface {
	Export(context.Context, <-chan protoreflect.Message) error
}

type NullExporter struct{}

func (s *NullExporter) Export(ctx context.Context, flows <-chan protoreflect.Message) error {
	for {
		<-flows
	}
}

func RunExporter(ctx context.Context, log *logrus.Logger, s Exporter, flows <-chan protoreflect.Message, errs chan<- error) {
	for {
		switch err := s.Export(ctx, flows); err {
		case io.EOF, context.Canceled:
			log.Debugf("sender: returning due to EOF or context cancelation")
			return
		case nil:
			continue
		default:
			if status.Code(err) == codes.Canceled {
				log.Debugf("sender: gRPC session cancelled")
				return
			}
			log.Debugf("sender: returing with an error - %s", err)
			errs <- err
			return
		}
	}
}
