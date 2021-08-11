GOBIN ?= $(shell go env GOPATH)/bin

CA_FILES := ca.csr ca-key.pem ca.pem
SERVER_CERT_FILES := test-server.csr test-server-key.pem test-server.pem
CLIENT_CERT_FILES := test-client.csr test-client-key.pem test-client.pem

all: $(SERVER_CERT_FILES) $(CLIENT_CERT_FILES)

clean:
	rm -f $(SERVER_CERT_FILES) $(CLIENT_CERT_FILES) $(CA_FILES)

$(CA_FILES): ca.json
	${GOBIN}/cfssl gencert \
		-initca ca.json \
	| ${GOBIN}/cfssljson -bare ca

$(SERVER_CERT_FILES): test-server.json config-server.json $(CA_FILES)
	${GOBIN}/cfssl gencert \
		-ca ca.pem \
		-ca-key ca-key.pem \
		-config config-server.json \
		-profile test-server \
		test-server.json \
	| ${GOBIN}/cfssljson -bare test-server

$(CLIENT_CERT_FILES): test-client.json config-client.json $(CA_FILES)
	${GOBIN}/cfssl gencert \
		-ca ca.pem \
		-ca-key ca-key.pem \
		-config config-client.json \
		-profile test-client \
		test-client.json \
	| ${GOBIN}/cfssljson -bare test-client
