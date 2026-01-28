---
layout: post
title: "Deploy 09: ScyllaDB with TLS Gateway and Istio Ambient Mode"
exclude_from_feed: true
pinned: false
excerpt: A deployable prototype implementing ScyllaDB inside minikube with connectivity via Istio TLS Gateway.
series: "Server Deployments"
series_part: 4
categories: [kubernetes, scylladb, istio, tls, security]
tags: [scylladb, kubernetes, istio, ambient-mode, tls, mtls, cert-manager, gateway-api]
---

## Project Overview

This project demonstrates a test deployment of ScyllaDB on Kubernetes with enterprise-grade security features. The architecture implements TLS termination at an Istio Gateway, combined with automatic mTLS between services using Istio's ambient mode. This setup provides encrypted communication from external clients while maintaining zero-trust security within the cluster.

The key innovation is the separation of concerns: external TLS termination at the gateway enables future automation of certificate rotation with minimal downtime, while Istio ambient mode handles internal mTLS transparently without sidecar injection.

The automated short-lived certificate rotation issue is that ScyllaDB (and Cassandra) do not support sighup signals for rereading certificate secrets. Thus the process for rotating certificates within the scyllaDB pods requires that the secrets be refreshed and then the pods restarted. For short-lived certificate rotation this becomes an unexceptable downtime burden.

**Note on Post Quantum hybrid TLS -** Initially I was attempting to use Post Quantum hybrid TLS algorithms as several notes indicate that with Istio 1.28 it is supported. The issue I found is that the standard envoy proxy included does not support the PQ algorithms. It requires a special build of the proxy to support PQ. The other issue is that the java TLS does not support the TLS alogrithms and would require modifications to the TLS provider in order to support. As it is presumed these issues will be resolved within 6 - 9 months with current upgrade cycles, I decided it was not worth it going to special efforts at this time in order to support PQ.   

## Architecture

### Components

**Infrastructure Layer:**
- Minikube cluster with MetalLB load balancer
- Istio service mesh in ambient mode
- cert-manager for certificate lifecycle management
- Kubernetes Gateway API for modern ingress

**Database Layer:**
- ScyllaDB StatefulSet with 3 replicas
- Headless service for inter-node communication
- CQL service for client connections
- Persistent storage with volume claims

**Security Layer:**
- Self-signed CA with cert-manager
- TLS certificate for gateway termination
- Automatic mTLS between pods via Istio ambient
- Authentication via PasswordAuthenticator
- Authorization via CassandraAuthorizer

**Client Layer:**
- Java client with embedded TLS proxy
- Environment-aware configuration
- Support for both local and Kubernetes deployments

### Network Flow

```
External Client (plaintext)
    ↓
Local TLS Proxy (Java same JVM)
    ↓ [TLS encryption]
Istio Gateway (LoadBalancer)
    ↓ [TLS termination]
    ↓ [mTLS via ambient]
ScyllaDB Service (ClusterIP)
    ↓ [mTLS via ambient]
ScyllaDB Pods
```

## Key Features

### 1. TLS Termination at Gateway

The Istio Gateway terminates TLS connections from external clients, providing a single point for certificate management. This architecture enables:

- **Certificate rotation automation**: Future projects can automate short-lived certificate rotation without touching database pods
- **Simplified client configuration**: Clients only need the CA certificate, not individual pod certificates
- **Centralized security policy**: All external connections pass through a single, auditable entry point

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: scylladb-gateway
spec:
  gatewayClassName: istio
  listeners:
  - name: cql
    port: 9041
    protocol: TLS
    tls:
      mode: Terminate
      certificateRefs:
      - kind: Secret
        name: scylladb-credential
```

### 2. Istio Ambient Mode

Unlike traditional sidecar-based service meshes, Istio's ambient mode provides mTLS without injecting proxy containers into every pod. Benefits include:

- **Reduced resource overhead**: No sidecar containers consuming CPU and memory
- **Simplified operations**: No need to restart pods for mesh updates
- **Transparent security**: mTLS automatically enabled by namespace label

```bash
kubectl label namespace scylladb istio.io/dataplane-mode=ambient
```

### 3. Environment-Aware Client

The Java client (`ScyllaDBTLS.java`) automatically detects its environment and configures itself accordingly:

```java
// Detects Kubernetes environment
private static boolean isKubernetes() {
    return System.getenv("KUBERNETES_SERVICE_HOST") != null;
}

// Adjusts configuration based on environment
private static final String GATEWAY_HOST = getEnv(
    "GATEWAY_HOST", 
    isKubernetes() ? "scylladb-gateway.scylladb.svc.cluster.local" : "10.1.1.12"
);
```

This enables the same code to run in local development, CI/CD pipelines, and production Kubernetes clusters without modification.

### 4. Embedded TLS Proxy

The client includes an embedded TLS proxy (`LocalTLSProxy.java`) that handles encryption transparently. The reason for this is that CQLsh, the scylladb/cassandra client assumes that if it is configured for TLS then the TLS connection is terminated at the ScyllaDB pods. Terminating the CQLsh tls at the Gateway throws errors even when the ScyllaDB pods are not configured to accept TLS connections.

This allows applications without native TLS support to communicate with TLS-enabled services:

- Accepts plaintext connections locally on port 9042
- Establishes TLS connection to gateway on port 9041
- Forwards data bidirectionally with full encryption

```java
// Start embedded proxy
proxy = new LocalTLSProxy(LOCAL_PORT, GATEWAY_HOST, GATEWAY_PORT, CERT_PATH);
proxy.start();

// Connect through proxy with plaintext driver
session = CqlSession.builder()
    .addContactPoint(new InetSocketAddress(LOCAL_IP, LOCAL_PORT))
    .withLocalDatacenter(DC)
    .build();
```

## Implementation Details

### Certificate Management

The project uses a two-tier certificate hierarchy managed by cert-manager:

**Root Issuer (Self-Signed):**
```yaml
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: root-tls-cert-issuer
spec:
  selfSigned: {}
```

**CA Issuer (Signed by Root):**
```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: tls-cert-issuer
spec:
  isCA: true
  commonName: scylladb.example.com
  secretName: scylladb-credential
  issuerRef:
    name: root-tls-cert-issuer
```

**Service Certificate:**
```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: syclladb-credential
spec:
  dnsNames:
    - '*.scylladb.scylladb.svc.cluster.local'
    - scylladb.example.com
  ipAddresses:
    - 127.0.0.1
    - 10.1.1.12
  secretName: scylladb-credential
  issuerRef:
    name: tls-cert-issuer
```

### ScyllaDB Configuration

The StatefulSet deploys ScyllaDB with production-ready settings:

**Resource Configuration:**
```yaml
args:
  - --smp=1                    # Single CPU core
  - --memory=768M              # Memory limit
  - --overprovisioned=1        # Development mode
  - --developer-mode=1         # Relaxed requirements
```

**Authentication:**
```yaml
- --authenticator=PasswordAuthenticator
- --authorizer=CassandraAuthorizer
```

**Cluster Formation:**
```yaml
env:
  - name: SCYLLA_SEEDS
    value: "scylladb-0.headless-svc.scylladb.svc.cluster.local:7000,..."
```

### Java Client Architecture

The client consists of three main components:

**1. SSLContextBuilder.java**
- Loads CA certificate from filesystem
- Creates trusted KeyStore
- Initializes SSLContext for TLS connections

**2. LocalTLSProxy.java**
- Runs local TCP server on port 9042
- Accepts plaintext connections from CQL driver
- Creates TLS socket to remote gateway
- Forwards data bidirectionally with thread-per-connection model

**3. ScyllaDBTLS.java**
- Main application class
- Environment detection and configuration
- Embedded proxy management
- CQL session lifecycle management

## Deployment Process

### Prerequisites

```bash
# Start Minikube with appropriate resources
minikube start --cpus 4 --memory 12288 --vm-driver docker \
  --cni kindnet --disk-size 100g

# Enable required addons
minikube addons enable dashboard
minikube addons enable metallb

# Configure MetalLB IP range
minikube addons configure metallb
```

### Install Gateway API and Istio

```bash
# Install Gateway API CRDs
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/experimental-install.yaml

# Install Istio in ambient mode
istioctl install --set values.pilot.env.PILOT_ENABLE_ALPHA_GATEWAY_API=true \
  --set profile=ambient --skip-confirmation
```

### Install cert-manager

```bash
# Create namespace
kubectl create namespace cert-manager

# Deploy CRDs
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.19.2/cert-manager.crds.yaml

# Install via Helm with Gateway API support
helm install cert-manager --version 1.19 jetstack/cert-manager \
  --namespace cert-manager \
  --set config.enableGatewayAPI=true \
  --set "extraArgs={--feature-gates=ExperimentalGatewayAPISupport=true}"
```

### Deploy ScyllaDB

```bash
# Create namespace
kubectl create namespace scylladb

# Deploy certificate issuers
kubectl apply -f root-tls-cert-issuer.yaml -n scylladb
kubectl apply -f tls-cert-issuer.yaml -n scylladb

# Deploy ScyllaDB components
kubectl apply -f scylladb-configmap.yaml -n scylladb
kubectl apply -f scylladb-service.yaml -n scylladb
kubectl apply -f scylladb-statefulset.yaml -n scylladb

# Wait for pods to be ready
kubectl wait --for=condition=Ready pods -l app=scylladb -n scylladb --timeout=300s
```

### Deploy Gateway and Enable Ambient

```bash
# Deploy gateway and TCPRoute
kubectl apply -f scylladb-gateway.yaml -n scylladb

# Wait for gateway to be programmed
kubectl wait --for=condition=Programmed gateway/scylladb-gateway \
  -n scylladb --timeout=120s

# Enable ambient mode (automatic mTLS)
kubectl label namespace scylladb istio.io/dataplane-mode=ambient
```

### Verify Cluster Formation

```bash
# Check node status (wait for all nodes to show UN)
kubectl exec -it scylladb-0 -n scylladb -- nodetool status

# Expected output:
# Datacenter: datacenter1
# Status=Up/Down
# State=Normal/Leaving/Joining/Moving
# --  Address        Load       Tokens  Owns    Host ID                               Rack
# UN  10.244.0.123   123 KB     256     100.0%  abc-123                               rack1
# UN  10.244.0.124   125 KB     256     100.0%  def-456                               rack1
# UN  10.244.0.125   124 KB     256     100.0%  ghi-789                               rack1
```

### Extract CA Certificate

```bash
# Extract CA certificate for Java client
kubectl get secret scylladb-credential -n scylladb \
  -o "jsonpath={.data['ca\.crt']}" | base64 -d > ca.crt
```

### Run Java Client

```bash
# From Eclipse or command line
cd proto-cass
mvn clean compile
mvn exec:java -Dexec.mainClass="learn.ScyllaDBTLS"
```

## Testing and Verification

### Gateway Connectivity

```bash
# Get gateway external IP
kubectl get gateway scylladb-gateway -n scylladb

# Test TLS connection
openssl s_client -connect <GATEWAY_IP>:9041 \
  -CAfile ca.crt -showcerts
```

### Client Operations

The Java client performs a complete test sequence:

1. **Keyspace creation:**
```cql
CREATE KEYSPACE IF NOT EXISTS mykeyspace 
WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1}
```

2. **Table creation:**
```cql
CREATE TABLE IF NOT EXISTS mykeyspace.mytable 
(id int PRIMARY KEY, name text)
```

3. **Data insertion:**
```cql
INSERT INTO mykeyspace.mytable (id, name) VALUES (1, 'John Doe')
INSERT INTO mykeyspace.mytable (id, name) VALUES (2, 'Jane Smith')
INSERT INTO mykeyspace.mytable (id, name) VALUES (3, 'Alice Johnson')
```

4. **Data retrieval:**
```cql
SELECT * FROM mykeyspace.mytable
```

Expected output:
```
=== Query Results ===
  ID: 1 | Name: John Doe
  ID: 2 | Name: Jane Smith
  ID: 3 | Name: Alice Johnson
=====================
```

### mTLS Verification

```bash
# Verify ambient mode is active
kubectl get pods -n scylladb -o jsonpath='{.items[*].metadata.labels.istio\.io/dataplane-mode}'

# Check Istio waypoint for encrypted traffic
istioctl proxy-config secret -n scylladb deploy/scylladb-gateway
```

## Security Considerations

### External Security (TLS at Gateway)

- **Certificate validity**: Certificates include IP addresses and DNS names for flexibility
- **TLS termination**: All external traffic decrypted at gateway, not at database pods
- **Certificate rotation**: Future automation can update gateway certificates without touching database
- **Cipher suites**: Modern TLS 1.3 with secure cipher suites (configurable via annotations)

### Internal Security (Istio mTLS)

- **Automatic encryption**: All pod-to-pod communication automatically encrypted
- **Zero-trust networking**: No pod trusts another without cryptographic proof
- **Identity-based authorization**: Future RBAC policies can leverage Istio identities
- **No sidecar overhead**: Ambient mode eliminates per-pod proxy containers

### Database Security

- **Authentication required**: PasswordAuthenticator enforces username/password
- **Authorization enabled**: CassandraAuthorizer allows fine-grained permissions
- **Credentials management**: Future integration with Kubernetes secrets or external vaults
- **Network isolation**: Services only exposed through controlled gateway

## Performance Considerations

### Development vs Production

This deployment is optimized for development with:
- Single CPU core per pod
- 768MB memory per pod
- Developer mode enabled
- Overprovisioned settings

For production, adjust:
```yaml
args:
  - --smp=8                    # Multiple CPU cores
  - --memory=32G               # Adequate memory
  - --overprovisioned=0        # Production mode
  - --developer-mode=0         # Disable development mode
```

### Proxy Overhead

The embedded TLS proxy adds minimal latency:
- Single memory copy per direction
- Thread-per-connection model (suitable for moderate connection counts)
- 8KB buffer size balances memory and performance
- Future optimization: Connection pooling, NIO-based architecture

### Ambient Mode Performance

Istio ambient mode provides better performance than sidecars:
- No in-pod proxy (reduced latency)
- Shared node-level proxy (better resource utilization)
- Reduced memory footprint per pod
- Lower CPU overhead for TLS operations

## Future Enhancements

### 1. Automated Certificate Rotation

The gateway-based TLS termination enables:
- Short-lived certificates (hours instead of days)
- Automated renewal via cert-manager
- Zero-downtime rotation (update gateway, not pods)
- Compliance with security policies requiring frequent rotation

Implementation approach:
```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
spec:
  duration: 2160h    # 90 days
  renewBefore: 360h  # 15 days before expiration
  secretName: scylladb-credential
  issuerRef:
    name: letsencrypt-prod  # Production CA
```

### 2. Client Certificate Authentication

Extend to mutual TLS with client certificates:
- Issue client certificates from same CA
- Configure gateway to require and verify client certs
- Map client certificates to database users
- Automate client certificate rotation

### 3. Multi-Datacenter Deployment

Scale to multiple Kubernetes clusters:
- Deploy ScyllaDB across regions
- Configure cross-datacenter replication
- Use Istio multi-cluster for mTLS between regions
- Implement geo-aware client routing

### 4. Observability Integration

Add comprehensive monitoring:
- Prometheus metrics from ScyllaDB
- Istio telemetry for traffic analysis
- Grafana dashboards for visualization
- Distributed tracing with Jaeger

### 5. Backup and Disaster Recovery

Implement automated backup:
- Scheduled snapshots to object storage
- Point-in-time recovery capability
- Cross-region backup replication
- Automated restore testing

## Lessons Learned

### 1. Ambient Mode vs Sidecars

Istio ambient mode significantly simplified deployment:
- No need to modify StatefulSet for sidecar injection
- Easier troubleshooting without proxy logs in every pod
- Better resource utilization in development clusters
- Transparent upgrades without pod restarts

Trade-off: Less per-pod control of policies, but acceptable for this use case.

### 2. Gateway API Benefits

Kubernetes Gateway API provided better abstractions than Ingress:
- Native support for TCP routing (TCPRoute)
- Built-in TLS termination
- Better integration with cert-manager
- Future-proof API design

### 3. Certificate Hierarchy Importance

Two-tier certificate hierarchy proved valuable:
- Root issuer for long-term stability
- Intermediate issuer for operational flexibility
- Easy to add more issuers for different services
- Simplified client configuration (only need root CA)

### 4. Embedded Proxy Pattern

The embedded TLS proxy pattern worked well for this project:
- No external dependencies for developers
- Consistent experience across environments
- Easy to debug and troubleshoot
- Self-contained solution

However, for production at scale, consider:
- Dedicated proxy infrastructure
- Connection pooling
- Load balancing across multiple proxies
- NIO-based implementation for higher throughput

## Troubleshooting Guide

### Gateway Not Programmed

```bash
# Check gateway status
kubectl describe gateway scylladb-gateway -n scylladb

# Verify Istio is running
kubectl get pods -n istio-system

# Check gateway controller logs
kubectl logs -n istio-system -l app=istio-ingressgateway
```

### Pods Not Joining Cluster

```bash
# Check seed node connectivity
kubectl exec -it scylladb-0 -n scylladb -- nodetool status

# Verify DNS resolution
kubectl exec -it scylladb-0 -n scylladb -- \
  nslookup scylladb-0.headless-svc.scylladb.svc.cluster.local

# Check pod logs
kubectl logs scylladb-0 -n scylladb
```

### TLS Connection Failures

```bash
# Verify certificate is present
kubectl get secret scylladb-credential -n scylladb

# Check certificate details
kubectl get certificate -n scylladb
kubectl describe certificate scylladb-credential -n scylladb

# Test TLS connection
openssl s_client -connect <GATEWAY_IP>:9041 -CAfile ca.crt
```

### Java Client Connection Issues

```java
// Enable debug logging
System.setProperty("javax.net.debug", "ssl:handshake");

// Verify certificate path
System.out.println("Certificate exists: " + 
  new File(CERT_PATH).exists());

// Check proxy is listening
netstat -an | grep 9042
```

## Conclusion

This project demonstrates a modern, secure, and maintainable approach to deploying ScyllaDB on Kubernetes. The combination of TLS-terminated gateway access and Istio ambient mode provides enterprise-grade security without the complexity of traditional service mesh deployments.

Key takeaways:
- Gateway-based TLS termination simplifies certificate management
- Istio ambient mode provides transparent mTLS without sidecars
- Environment-aware clients reduce configuration complexity
- Kubernetes Gateway API offers superior abstractions for modern workloads

The architecture is production-ready with appropriate resource adjustments, and the gateway-based approach enables future automation of certificate rotation for zero-downtime security updates.

## Repository Structure

```
deploy-09-scylladb/
├── deploy/
│   ├── kube/
│   │   ├── root-tls-cert-issuer.yaml      # Self-signed root CA
│   │   ├── tls-cert-issuer.yaml           # Intermediate CA issuer
│   │   ├── scylladb-configmap.yaml        # ScyllaDB configuration
│   │   ├── scylladb-service.yaml          # CQL and headless services
│   │   ├── scylladb-statefulset.yaml      # ScyllaDB pods
│   │   ├── scylladb-gateway.yaml          # Gateway with TLS termination
│   │   └── scylladb-gateway-tcp.yaml      # Alternative TCP gateway
│   └── deploy.sh                          # Automated deployment script
├── proto-cass/
│   ├── src/main/java/learn/
│   │   ├── ScyllaDBTLS.java               # Main client application
│   │   ├── LocalTLSProxy.java             # Embedded TLS proxy
│   │   └── SSLContextBuilder.java         # TLS context builder
│   ├── src/main/resources/
│   │   └── ca.crt                         # CA certificate (generated)
│   └── pom.xml                            # Maven dependencies
└── README.md                              # Project documentation
```

## References

- [ScyllaDB Documentation](https://docs.scylladb.com/)
- [Istio Ambient Mode](https://istio.io/latest/docs/ambient/)
- [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/)
- [cert-manager Documentation](https://cert-manager.io/docs/)
- [Cassandra Java Driver](https://apache.github.io/cassandra-java-driver/)

---

*This deployment serves as a foundation for building production-grade distributed database systems with modern security practices and operational excellence.*
