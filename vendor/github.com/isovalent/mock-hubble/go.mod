module github.com/isovalent/mock-hubble

go 1.16

require (
	github.com/cilium/cilium v1.10.3
	github.com/sirupsen/logrus v1.7.0
	github.com/ulikunitz/xz v0.5.10
	google.golang.org/grpc v1.33.2
)

replace github.com/optiopay/kafka => github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b
