---
layout: readme
title: Deploy-10 SoftHSM on Minikube with Kubernetes StatefulSets
exclude_from_feed: true
pinned: false
excerpt: A deployable prototype implementing Hardware Security Module (HSM) cryptographic services using SoftHSM in a Minikube Kubernetes environment with PKCS#11 integration and comprehensive key management capabilities.
series: "Server Deployments"
series_part: 5
categories: [kubernetes, softhsm, pkcs11, istio, security]
tags: [softhsm, kubernetes, istio, ambient-mode]
---

## 1 - Project Purpose

The purpose of this learning deployment prototype is to deploy a Software HSM (Hardware Security Module) service into Kubernetes Minikube for development and testing of cryptographic key management operations. This deployment demonstrates:

- **SoftHSM Integration**: Implementation of PKCS#11 compliant cryptographic operations using SoftHSM 2.6.1
- **Java Service Architecture**: Custom HSM service built with Java 21 and JCA/JCE APIs for comprehensive key operations
- **Kubernetes StatefulSet Deployment**: Persistent HSM token storage with proper volume management
- **Complete Key Lifecycle Management**: Key generation, wrapping, unwrapping, and secure deletion

The deployment uses Kubernetes YAML manifest files and deployment scripts for automated provisioning and testing.

It demonstrates a minimal java service client access to the softhsm functionality which is required for a
distributed application built using microservices. Softhsm becomes the trust anchor with a st of Master Keys which can
not be exported from the hsm. These are used to wrap master service keys which are used with HKDF to generate
individual user / service keys used to encrypt user / service data. The service keys are stored within OpenBao as are
the Master Keys. When a service starts, it obtains its collection of wrapped service keys, and sends them
individually to the hsm service for unwrapping. These keys, along with the appropriate hkdf information are
used to recreate the ephemeral user / service keys.

## 2 - Project Dependencies

### 2.1 Core Infrastructure

| Component       | Version |
| --------------- | ------- |
| Minikube        | 1.36.0+ |
| Kubernetes      | 1.31.0+ |
| Docker          | 27.2.0+ |
| Java (Eclipse Temurin) | 21 |
| SoftHSM         | 2.6.1   |

### 2.2 Computer Configuration

| Name       | Description                              |
| ---------- | ---------------------------------------- |
| Ubuntu     | 20.04.6 LTS or later                     |
| Processor  | Intel® Core™ i7-7700K CPU @ 4.20GHz × 8  |
| Memory     | 64 GB                                    |

### 2.3 Deploying the Core Infrastructure Dependencies

Instructions for deploying the Core Infrastructure Dependencies listed above are NOT included within this prototype as there are numerous targeted deployment instructions better suited for your particular OS and environment.

### 2.4 Dependencies Deployed within the Prototype (Optional)

| Deployed Component | Version | Purpose                          |
| ------------------ | ------- | -------------------------------- |
| NATS               | 2.10+   | Message broker for HSM requests  |
| Istio (Optional)   | 1.23.2+ | Service mesh for secure communication |
| MetalLB            | 0.9.6+  | Load balancer for external access |

## 3 - Deployment Architecture

### 3.1 HSM Service Components

The deployment consists of several key components:

**SoftHSM Container**: 
- Multi-stage Docker build compiling SoftHSM 2.6.1 from source
- Java 21 runtime with custom HSM service JAR
- PKCS#11 provider integration for cryptographic operations
- Persistent token storage using Kubernetes PVCs

**HSM Service Features**:
- Master key generation (AES-256, non-extractable)
- Service key generation (external 256-bit AES-GCM keys)
- Key wrapping/unwrapping with AES-KWP
- Key information retrieval and lifecycle management
- Health monitoring and status reporting

**StatefulSet Configuration**:
- Ordered pod deployment with stable network identities
- Persistent volume claims for HSM token storage
- Init containers for proper permissions setup
- Security contexts with restricted user privileges (UID 1000)

### 3.2 Cryptographic Workflow

The service implements a secure key management workflow suitable for integration with systems like OpenBao:

1. **Master Key Generation** (one-time setup): Generate non-extractable AES-256 master wrapping key in HSM
2. **Service Key Generation** (per-service): Generate 256-bit AES-GCM keys externally using SecureRandom
3. **Key Wrapping**: Wrap service keys with HSM master key for secure storage
4. **Key Storage**: Store wrapped keys in external vault (e.g., OpenBao)
5. **Runtime Unwrapping**: Unwrap keys on-demand for application encryption operations
6. **Memory Security**: Use keys in memory only, never store unwrapped

## 4 - Important Notes

### 4.1 Script Usage

**Note:**
1. *The commands within the shell files are meant to be run in sequence, either manually or as automated deployment scripts.*
2. *Each script contains a PROTODIR environment variable. You MUST update this for your directory paths.*
3. *The deployment assumes Minikube is installed and Docker environment is properly configured.*

### 4.2 Test Clients Provided

The project includes two test implementations:

**HSMDirectTest.java**: Direct in-container testing without NATS dependency
- Tests all HSM handlers directly within the service container
- Validates key generation, wrapping, unwrapping, and deletion
- Simulates complete OpenBao integration workflow (without installing OpenBao)
- Provides comprehensive test output and verification

**HSMService.java**: Full service implementation
- PKCS#11 integration with SoftHSM
- Optional NATS message broker support
- Complete JCA/JCE cryptographic API usage
- Comprehensive error handling and logging

## 5 - The Deployment Process

### 5.1 Deployment Script Overview (Step-02-DeploySofthsm.sh)

The main deployment script performs the following operations:

1. **Minikube Profile Selection**: Sets the target Kubernetes cluster (`bao`)
2. **Namespace Creation**: Creates `softhsm` namespace for HSM components
3. **Docker Image Build**: Compiles custom HSM service Docker image with SoftHSM
4. **ConfigMap Deployment**: Deploys SoftHSM configuration (token directory, logging, backend settings)
5. **Secrets Deployment**: Applies HSM PIN credentials (SO-PIN and User-PIN)
6. **StatefulSet Deployment**: Deploys HSM service with persistent volume claims
7. **Pod Readiness Wait**: Monitors pod status until ready (300s timeout)
8. **Service Deployment**: Creates headless service for StatefulSet
9. **Istio Integration**: Labels namespace for Istio ambient mesh (optional)
10. **Verification**: Tests SoftHSM functionality and runs integration test job

### 5.2 Image Build Process (buildHsmServiceImage.sh)

The image build script:

1. **Environment Setup**: Configures Minikube Docker environment
2. **File Verification**: Checks for required build artifacts (SoftHSM tarball, JAR, scripts)
3. **JAR Copy**: Copies compiled HSM service JAR to build context
4. **Docker Build**: Creates multi-stage image with SoftHSM and Java service
5. **Verification**: Provides commands to test and deploy the built image

### 5.3 Kubernetes Manifests

**softhsm-configmap.yaml**: SoftHSM configuration
- Token directory location (`/var/lib/softhsm/tokens`)
- Object store backend (SQLite database)
- Logging configuration
- Security settings

**softhsm-secrets.yaml**: PIN credentials
- Security Officer PIN (SO-PIN): `1234567890`
- User PIN: `123456`
- *Note: These are development credentials and should be changed for production*

**hsm-statefulset.yaml**: Main HSM service deployment
- Single replica with ordered deployment
- Init container for permissions setup
- Persistent volume for token storage (1Gi)
- Environment variables for HSM configuration
- Liveness and readiness probes using `softhsm2-util --show-slots`
- Resource limits: 1Gi memory, 500m CPU

**hsm-service.yaml**: Headless service
- Required for StatefulSet stable network identity
- ClusterIP: None
- Port 4222 (NATS convention)

**hsm-service-test.yaml**: Integration test job
- Runs HSMDirectTest in isolated container
- Validates all HSM operations
- TTL: 300 seconds after completion
- Uses same HSM service image with test entrypoint

## 6 - Key Operations Supported

### 6.1 Health Check
- **Subject**: `hsm.health`
- **Response**: Service status, HSM availability, timestamp

### 6.2 Key Generation
- **Subject**: `hsm.keys.generate`
- **Operation**: Generate master wrapping keys (AES-256, non-extractable)
- **Use Case**: One-time setup of master keys that never leave the HSM

### 6.3 Generate and Wrap Service Key
- **Operation**: Generate 256-bit AES-GCM key externally, wrap with master key
- **Process**: Uses SecureRandom → Wrap with HSM → Return wrapped key
- **Use Case**: Create service-specific encryption keys for OpenBao storage

### 6.4 Key Wrapping
- **Subject**: `hsm.keys.wrap`
- **Algorithm**: AES-KWP (Key Wrap with Padding)
- **Operation**: Wrap external keys with HSM master key
- **Use Case**: Protect keys before storage in external vaults

### 6.5 Key Unwrapping
- **Subject**: `hsm.keys.unwrap`
- **Operation**: Unwrap previously wrapped keys using master key
- **Use Case**: Runtime key retrieval for encryption operations

### 6.6 Key Management
- **List Keys**: Enumerate all keys in HSM token
- **Key Info**: Retrieve key metadata (algorithm, format, extractability)
- **Delete Key**: Securely remove keys from HSM token

## 7 - Entrypoint Scripts

### 7.1 hsm-service-entrypoint.sh (Production)

Initialization sequence for the main HSM service:

1. **Environment Validation**: Checks pod name, IP, and configuration
2. **Directory Setup**: Creates token directory with correct permissions
3. **Idempotent Token Init**: Initializes SoftHSM token if not already done
4. **Token Verification**: Displays available slots and token status
5. **Service Launch**: Starts Java HSM service with NATS connection

### 7.2 hsm-service-test-entrypoint.sh (Testing)

Test-specific initialization:

1. **Environment Setup**: Validates test configuration
2. **Directory Permissions**: Ensures proper token directory access
3. **Idempotent Token Check**: Verifies or creates test token
4. **Test Execution**: Runs HSMDirectTest with exit code propagation
5. **Comprehensive Validation**: Tests all HSM operations end-to-end

## 8 - Security Considerations

### 8.1 Access Control
- Service runs as non-root user (UID 1000)
- Security contexts drop all capabilities
- Read-only configuration mounts
- Secrets-based credential management

### 8.2 Key Protection
- Master keys marked as non-extractable
- Keys exist only in HSM token, never in plain text
- Wrapped keys use authenticated encryption (AES-KWP)
- Service keys cleared from memory after use

### 8.3 Network Security
- Optional Istio ambient mesh for mTLS between pods
- Headless service for internal StatefulSet communication
- ConfigMap and Secret separation for sensitive data

## 9 - Testing and Verification

### 9.1 Manual Verification Commands

```bash
# Check SoftHSM slots and tokens
kubectl exec -n softhsm hsm-service-0 -- softhsm2-util --show-slots

# View pod logs
kubectl logs -n softhsm hsm-service-0 -f

# Check test job results
kubectl logs -n softhsm job/hsm-service-test

# Port forward for external access (if using NATS)
kubectl port-forward -n softhsm svc/nats 4222:4222
```

### 9.2 Integration Test Coverage

The HSMDirectTest validates:

1. **Health Check**: Service availability and HSM readiness
2. **List Keys**: Token enumeration functionality
3. **Master Key Generation**: Non-extractable wrapping key creation
4. **Service Key Generation**: External key generation and wrapping
5. **Wrap/Unwrap**: Round-trip key protection validation
6. **Key Info**: Metadata retrieval accuracy
7. **Delete Key**: Secure key removal
8. **Complete Workflow**: End-to-end OpenBao integration simulation

## 10 - Things to Remember

1. **PROTODIR Variable**: Update the `PROTODIR` environment variable in all scripts to match your local directory structure
   ```bash
   PROTODIR="/media/tim/ExtraDrive1/Projects/deploy-10-softhsm/deploy"
   ```

2. **Minikube Profile**: The deployment targets a Minikube profile named `bao`. Adjust if using a different profile:
   ```bash
   CLUSTER="bao"
   minikube profile $CLUSTER
   ```

3. **Persistent Storage**: HSM tokens are stored in persistent volumes. Deleting the PVC will destroy all keys:
   ```bash
   # Warning: This deletes all keys!
   kubectl delete pvc -n softhsm softhsm-data-hsm-service-0
   ```

4. **Security Credentials**: The default PINs in `softhsm-secrets.yaml` are for development only:
   - SO-PIN: `1234567890`
   - User-PIN: `123456`
   - **Change these for production deployments**

5. **Image Build Context**: The build script copies the HSM service JAR from:
   ```bash
   ../../hsm-service/target/hsm-service.jar
   ```
   Ensure your Maven build completes successfully before running the Docker build.

6. **SoftHSM Source**: The Dockerfile expects `softhsm-2.6.1.tar.gz` in the build directory. Download from:
   ```
   https://github.com/opendnssec/SoftHSMv2/releases/download/2.6.1/softhsm-2.6.1.tar.gz
   ```

7. **StatefulSet Naming**: Pods are named with ordinal suffixes:
   ```
   hsm-service-0, hsm-service-1, hsm-service-2, ...
   ```
   The headless service provides stable DNS names:
   ```
   hsm-service-0.hsm-service-headless.softhsm.svc.cluster.local
   ```

8. **Resource Requirements**: The deployment requests:
   - Memory: 512Mi (limit: 1Gi)
   - CPU: 200m (limit: 500m)
   - Storage: 1Gi per pod
   Adjust based on your workload and cluster capacity.

9. **NATS Integration**: While the service supports NATS, it can run standalone. Set `HSM_MODE=test` to disable NATS connectivity:
   ```yaml
   env:
     - name: HSM_MODE
       value: "test"
   ```

10. **Istio Ambient Mesh**: The deployment script optionally labels the namespace for Istio:
    ```bash
    kubectl label namespace softhsm istio.io/dataplane-mode=ambient --overwrite
    ```
    This enables automatic mTLS between pods. Remove the label if Istio is not installed.

## 11 - Future Enhancements

Potential improvements for production deployments:

1. **Multi-Replica Support**: Scale StatefulSet for high availability
2. **External PKI Integration**: Replace self-signed certificates with enterprise CA
3. **Audit Logging**: Comprehensive key operation auditing
4. **Key Rotation**: Automated master key rotation procedures
5. **Backup/Restore**: Token backup and disaster recovery procedures
6. **Metrics Export**: Prometheus metrics for monitoring HSM operations
7. **Hardware HSM Migration**: Adapt service for hardware HSM (e.g., Thales, Gemalto)
8. **OpenBao Integration**: Direct integration with OpenBao for key storage
9. **Performance Optimization**: Connection pooling and caching for high-throughput scenarios
10. **Compliance**: FIPS 140-2 validation for regulated environments

## 12 - References

1. **SoftHSM Project**: https://github.com/opendnssec/SoftHSMv2
2. **PKCS#11 Standard**: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/
3. **Java Cryptography Architecture**: https://docs.oracle.com/en/java/javase/21/security/
4. **Kubernetes StatefulSets**: https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/
5. **NATS Messaging**: https://docs.nats.io/
6. **OpenBao**: https://openbao.org/docs/
7. **AES Key Wrap**: RFC 3394 and RFC 5649 (AES-KWP)
8. **Istio Ambient Mesh**: https://istio.io/latest/docs/ambient/

---

**License**: MIT  
**Author**: Tim Snyder  
**Last Updated**: January 27, 2026
