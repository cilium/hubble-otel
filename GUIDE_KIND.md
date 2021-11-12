## Basic Setup

Create a 2-node cluster using kind:
```
cat > kind-config.yaml << EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.21.1@sha256:fae9a58f17f18f06aeac9772ca8b5ac680ebbed985e266f711d936e91d113bad
    kubeadmConfigPatches:
      - |
        apiVersion: kubeadm.k8s.io/v1beta2
        kind: InitConfiguration
        nodeRegistration:
          taints: []
  - role: worker
    image: kindest/node:v1.21.1@sha256:fae9a58f17f18f06aeac9772ca8b5ac680ebbed985e266f711d936e91d113bad
networking:
  disableDefaultCNI: true
  podSubnet: "10.244.0.0/16"
  serviceSubnet: "10.245.0.0/16"
EOF
kind create cluster --config kind-config.yaml
```

Install Cilim with Hubble enabled:
```
cilium install && cilium hubble enable
```

Install cert-manager as it's a dependency of the OpenTelemetry operator:
```
kubectl apply -k github.com/cilium/kustomize-bases/cert-manager
```

Wait for cert-manager to become ready:
```
(
  set -e
  kubectl wait deployment --namespace="cert-manager" --for="condition=Available" cert-manager-webhook cert-manager-cainjector cert-manager --timeout=3m
  kubectl wait pods --namespace="cert-manager" --for="condition=Ready" --all --timeout=3m
  kubectl wait apiservice --for="condition=Available" v1.cert-manager.io v1.acme.cert-manager.io --timeout=3m
  until kubectl get secret --namespace="cert-manager" cert-manager-webhook-ca 2> /dev/null ; do sleep 0.5 ; done
)
```

Deploy Jaeger operator:
```
kubectl apply -k github.com/cilium/kustomize-bases/jaeger
```

Configure a memory-backed Jaeger instance:
```
cat > jaeger.yaml << EOF
apiVersion: jaegertracing.io/v1
kind: Jaeger
metadata:
  name: jaeger-default
  namespace: jaeger
spec:
  strategy: allInOne
  storage:
    type: memory
    options:
      memory:
        max-traces: 100000
  ingress:
    enabled: false
  annotations:
    scheduler.alpha.kubernetes.io/critical-pod: ""
EOF
kubectl apply -f jaeger.yaml
```


Deploy OpenTelemetry operator:
```
kubectl apply -k github.com/cilium/kustomize-bases/opentelemetry
```

Configure a collector with Hubble receiver and Jaeger exporter:
```
cat > otelcol.yaml << EOF
apiVersion: opentelemetry.io/v1alpha1
kind: OpenTelemetryCollector
metadata:
  name: otelcol-hubble
  namespace: kube-system
spec:
  mode: daemonset
  image: ghcr.io/cilium/hubble-otel/otelcol:v0.1.0-rc.4
  env:
    - name: NODE_NAME
      valueFrom:
        fieldRef:
          fieldPath: spec.nodeName
  volumes:
    #- name: cilium-run
    #  hostPath:
    #    path: /var/run/cilium
    #    type: Directory
    - name: hubble-tls
      projected:
        defaultMode: 256
        sources:
          - secret:
              name: hubble-relay-client-certs
              items:
                - key: tls.crt
                  path: client.crt
                - key: tls.key
                  path: client.key
                - key: ca.crt
                  path: ca.crt
  volumeMounts:
    #- name: cilium-run
    #  mountPath: /var/run/cilium
    - name: hubble-tls
      mountPath: /var/run/hubble-tls
      readOnly: true
  config: |
    receivers:
      otlp:
        protocols:
          grpc:
            endpoint: 0.0.0.0:55690
      hubble:
        endpoint: \${NODE_NAME}:4244 # unix:///var/run/cilium/hubble.sock
        buffer_size: 100
        include_flow_types:
          traces: ["l7"]
        tls:
          insecure_skip_verify: true
          ca_file: /var/run/hubble-tls/ca.crt
          cert_file: /var/run/hubble-tls/client.crt
          key_file: /var/run/hubble-tls/client.key
    processors:
      batch:
        timeout: 30s
        send_batch_size: 100

    exporters:
      logging:
        loglevel: debug
      jaeger:
        endpoint: jaeger-default-collector.jaeger.svc.cluster.local:14250
        tls:
          insecure: true

    service:
      telemetry:
        logs:
          level: info # debug
      pipelines:
        traces:
          receivers: [hubble, otlp]
          processors: [batch]
          exporters: [jaeger]

EOF
kubectl apply -f otelcol.yaml
```

This configuration will deploy the collector as a DaemonSet, you can see the pods by running:
```
kubectl get pod -n kube-system -l app.kubernetes.io/name=otelcol-hubble-collector
```

To view the logs, run:
```
kubectl logs -n kube-system -l app.kubernetes.io/name=otelcol-hubble-collector
```

You should now be able to view traces produced by Hubble in the Jaeger UI, which you can access by port-forwarding:
```
kubectl port-forward svc/jaeger-default-query -n jaeger 16686
```

## Getting More Visibility

The basic setup is done now. However, you probably won't find anything interesting just yet.
Let's get more traces generated, and enable DNS & HTTP visibility in Cilium.

First, deploy podinfo app:
```
kubectl apply -k github.com/cilium/kustomize-bases/podinfo
```

Enable HTTP visibility for the podinfo app and all of DNS traffic:
```
cat > visibility-policies.yaml << EOF
---
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: default-allow
spec:
  endpointSelector: {}
  egress:
    - toEntities:
        - cluster
        - world
    - toEndpoints:
        - {}
---
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: dns-visibility
spec:
  endpointSelector: {}
  egress:
    - toEndpoints:
      - matchLabels:
          k8s:io.kubernetes.pod.namespace: kube-system
          k8s:k8s-app: kube-dns
      toPorts:
      - ports:
        - port: "53"
          protocol: ANY
        rules:
          dns:
            - matchPattern: "*"
    - toFQDNs:
      - matchPattern: "*"
    - toEndpoints:
      - {}
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: http-visibility
  namespace: podinfo
spec:
  endpointSelector: {}
  egress:
    - toPorts:
      - ports:
        - port: "9080"
          protocol: TCP
        rules:
          http:
          - method: ".*"
    - toEndpoints:
      - {}
EOF
kubectl apply -f visibility-policies.yaml
```

The podinfo app will produce Jaeger traces already, however to collect these
a sidecar is [recommended](https://github.com/jaegertracing/jaeger-client-python/issues/47#issuecomment-303119229).

Add sidecard config:
```
cat > otelcol-podinfo.yaml << EOF
apiVersion: opentelemetry.io/v1alpha1
kind: OpenTelemetryCollector
metadata:
  name: otelcol-podinfo
  namespace: podinfo
spec:
  mode: sidecar
  env:
    - name: NODE_NAME
      valueFrom:
        fieldRef:
          fieldPath: spec.nodeName
  config: |
    receivers:
      otlp:
        protocols:
          http: {}
    exporters:
      logging:
        loglevel: info
      otlp:
        endpoint: \${NODE_NAME}:55690

    service:
      telemetry:
        logs:
          level: info
      pipelines:
        traces:
          receivers: [otlp]
          exporters: [otlp, logging]

EOF
kubectl apply -f otelcol-podinfo.yaml
```

Re-create podinfo pods to add the sidecars:
```
kubectl delete pods -n podinfo --all --wait=false
```

Run hey:
```
TODO
```
