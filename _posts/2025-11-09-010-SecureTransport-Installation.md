---
layout: readme
title: Secure Transport Research Project - Part 2 - Installation 
pinned: false
date: 2025-11-09 16:06:11 +0000
categories: [Security, Cryptography, kubernetes, NATS, deployment]
tags: [openbao, nats, mtls, multi-cluster]
series: "SecureTransport Research Prototype"
series_part: 2
---

# 1 Installation Overview

## 1.1 What We're Building

**A research prototype messaging system** exploring practical solutions to the operational challenges of:

1. **Intermediate CA certificate rotation** (main innovation - not just leaf certificates)
   - Intermediate Certificates are generally what clients use for authenticating servers during TLS handshakes
2. **Short-lived intermediate certificate automation** (90 days to hourly/daily rotation)
3. **Post-quantum cryptography at scale** (Kyber + Dilithium)
4. **High-frequency key rotation** (15-minute rotation, 1-hour expiry) - AES-GCM-256 with HKDF
5. **Cryptographic authorization enforcement** (not just authentication)
6. **Zero-downtime security updates** (no service disruption during rotation)
7. **3-5 second rotation window** (during client reconnections, producer and consumer rotation window should be minimal)

**Built to Validate Real-World Approaches:**
- **Microservices architectures** with dozens / hundreds of communicating services
- **High-throughput messaging** where PQC overhead matters
- **Regulatory compliance** requiring audit trails and cryptographic proofs
- **Operational automation** that eliminates manual certificate management
- **Future-ready infrastructure** for quantum-safe cryptography mandates
- **Multi-cluster Capable by design** the prototype deployment is across 3 minikube clusters.

**Technology Foundation:**
- **Vert.x 5.0**: Reactive, non-blocking architecture minimizes PQC overhead
- **Kubernetes-native**: Cert-Manager, Fabric8, native resource watching
- **NATS messaging**: High-performance, mTLS-secured transport
- **OpenBao**: Secrets management with FIPS-compliant cryptography
- **BouncyCastle - including FIPS**: Cryptographic operations
- **Java 21**: Modern Java with enhanced performance

---

## 1.2 Prerequisistes
This prototype was developed and tested using the following:
- **Ubuntu**             - 20.04.6 LTS
- **Minikube**           - 1.35.0
- **Kubernetes**         - 1.31.0
- **Docker**             - 27.2.0
- **Metallb**            - 0.9.6
- **Cert-manager**       - 1.17.5
- **Istio**              - 1.26.1
- **OpenBao**            - 2.2.0
- **Kubernetes Gateway** - 1.2.0
- **OpenSSL**            - 3.4.0

Laptop Machine configuration:
     Processor - Intel® Core™ i7-7700K CPU @ 4.20GHz × 8 
     Memory    - 64 GB

It is very important that the machine you are deploying on has enough memory and 
processor core to support the installation of the 3 minikube clusters.

### Hardware Requirements
- **Minimum**: 32GB RAM, 4 cores (Need to adjust minikube startup parameters)
- **Recommended**: 64GB RAM, 8 cores (as tested)
- **Disk**: 300GB+ free space for cluster images

### Required Software
Prior to installing this prototype the following must be deployed:

| Tool | Version | Install Command | Verify |
|------|---------|----------------|--------|
| Minikube | 1.35.0+ | [Install Guide](https://minikube.sigs.k8s.io/docs/start/) | `minikube version` |
| kubectl | 1.31.0+ | [Install Guide](https://kubernetes.io/docs/tasks/tools/) | `kubectl version` |
| Docker | 27.2.0+ | [Install Guide](https://docs.docker.com/engine/install/ubuntu/) | `docker --version` |
| Helm | 3.0+ | `curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 \| bash` | `helm version` |
| istioctl | 1.26.1+ | `curl -L https://istio.io/downloadIstio \| sh -` | `istioctl version` |
| jq | 1.6+ | `sudo apt install jq` | `jq --version` |
| OpenSSL | 3.4.0+ | `sudo apt install openssl` | `openssl version` |

---
## 1.3 The Three Clusters - Highlevel View

### 1.3.1 Services and Infrastructure

<img src="/assets/images/architecture-services.jpg" alt="Alt text" width="500">

## 1.3.1 Deployment Topology

<img src="/assets/images/architecture-deployment.jpg" alt="Alt text" width="500">

---

## 1.4 The Deployment Steps
The overall steps are:
1. Download the project - git clone https://github.com/t-snyder/010-SecureTransport.git
2. Set the PROTODIR var to your directory - PROTODIR=/<dirpath>/010-SecureTransport/deploy
3. Edit the necessary path variables within each of the scripts
4. Run the scripts

## 1.5 The Deployment Scripts
- /bin/bash $PROTODIR/scripts/Step-01a-DeployOpenBaoMinikubeCluster.sh
- /bin/bash $PROTODIR/scripts/Step-01b-DeployServersMinikubeCluster.sh
- /bin/bash $PROTODIR/scripts/Step-01c-DeployServicesMinikubeCluster.sh

- /bin/bash $PROTODIR/scripts/Step-02-OpenBao-InstallWithTLS.sh      
- /bin/bash $PROTODIR/scripts/Step-03-OpenBao-Initialize-JoinUnseal.sh
- /bin/bash $PROTODIR/scripts/Step-04-OpenBao-ConfigureCA.sh
- /bin/bash $PROTODIR/scripts/Step-05-OpenBao-ConfigureAuthAndIssuers.sh
- /bin/bash $PROTODIR/scripts/Step-06-DeployNatsToServers.sh
- /bin/bash $PROTODIR/scripts/Step-07-DeployMetadataSvcToBaoCluster.sh
- /bin/bash $PROTODIR/scripts/Step-08-DeployWatcherToServersCluster.sh
- /bin/bash $PROTODIR/scripts/Step-09-DeployAuthController.sh
- /bin/bash $PROTODIR/scripts/Step-10-DeployGatekeeper.sh

---

## 1.6 Quick Start

**Total deployment time: ~30 minutes**

1. Set your base directory
export PROTODIR=/your-local-path/010-SecureTransport/deploy

2. Deploy all three clusters (can run in parallel)
- cd $PROTODIR/scripts
-    ./Step-01a-DeployOpenBaoMinikubeCluster.sh &
-    ./Step-01b-DeployServersMinikubeCluster.sh &
-    ./Step-01c-DeployServicesMinikubeCluster.sh &

3. Configure OpenBao (must run sequentially)
-     ./Step-02-OpenBao-InstallWithTLS.sh
-     ./Step-03-OpenBao-Initialize-JoinUnseal.sh
-     (Manually Start port-forward in separate terminal: ./Helpers/openbao-portforward.sh)
-     ./Step-04-OpenBao-ConfigureCA.sh
-     ./Step-05-OpenBao-ConfigureAuthAndIssuers.sh

4. Deploy services
-     ./Step-06-DeployNatsToServers.sh
-     (Manually start port-forward in separate terminal: ./Helpers/Nats-portforward.sh
-     ./Step-07-DeployMetadataSvcToBaoCluster.sh &
-     ./Step-08-DeployWatcherToServersCluster.sh &
-     ./Step-09-DeployAuthController.sh &
-     ./Step-10-DeployGatekeeper.sh &

---

# 2.0 Creating the clusters

The first 3 scripts - all denoted as Step-01x - deploy the 3 minikube clusters.
They can be run in parallel safely (assuming processing capacity and memory).
Generally I set up 3 different terminals, one for each cluster and then a separate
terminal for the Port Forwards. After setting up the terminals, you can edit the
scripts/Helpers/Set-Directory.sh to first set the PROTODIR in each terminal, and then
run the 3 minikube setup scripts. Note that they all follow the same pattern and use
the same commands. The only differences are
- The minikube profile used - bao, servers or services
- The namespace created at the end - openbao, nats, <none> 

**Key actions - Step-01a Used as an example:**
1. **Starts Minikube** with profile "bao"
2. **Enables dashboard** for visual monitoring
3. **Enables MetalLB** (load balancer) and configures IP range
4. **Installs Gateway API CRDs** (needed by cert-manager)
5. **Installs Istio ambient mode** (service mesh for mTLS)
6. **Installs cert-manager** (automates certificate lifecycle)
7. **Creates `openbao` namespace**

**Result:** Empty cluster ready to run OpenBao.

---
**==========================================================================================**
**Important Note - Each of the following scripts (Step-02 through Step-10) sets certain path variables within the script. These should be set to your environment prior to running the script.**
**==========================================================================================**

---

# 3.0 Install OpenBao with TLS
The deployment scripts Step-02.. through Step-05.. deploy OpenBao and configure
it for both Secrets and PKI. The system uses the OpenBao PKI for both root and intermediate
Certificates and certificate signing. 

## 3.1 Step 02 - Deploy OpenBao (Vault Opensource fork) with TLS enabled on Kubernetes
- **The Script**: $PROTODIR/scripts/Step-02-OpenBao-InstallWithTLS.sh
- **The Problem**: OpenBao needs TLS to start, but cert-manager (which issues certs) runs inside Kubernetes.

**The Solution**: Bootstrap with self-signed CA
1. cert-manager creates a **self-signed CA** (openbao-ca-secret)
2. Uses that CA to sign **OpenBao's server certificate** (openbao-tls)
3. OpenBao starts with this certificate
4. Later, OpenBao becomes the CA for **all other services**

### Steps in Script Process
- Creates cert-manager issuers and certificates
- Waits for TLS secrets
- Patches the openbao-tls secret with expected key names
- Deploys OpenBao using Helm with 3 replicas/raft HA

### Certificate Setup
The deployment script deploys the following manifests:
- **Namespace** $PROTODIR/openbao/kube/openbao-namespace.yaml 
- **Issuers** $PROTODIR/openbao/kube/openbao-issuer.yaml (Self-signed root, and Issuer)
- **Certificate** $PROTODIR/openbao/kube/openbao-certs.yaml

The cert-manager issuer resource generates the openbao-ca-secret secret.
The cert-manager certificate resource generates the openbao-tls secret.

### Secret Patching

```bash
# OpenBao expects specific key names in the secret
kubectl patch secret openbao-tls -n openbao --type='json' -p="[
  {\"op\": \"add\", \"path\": \"/data/openbao.key\", \"value\": \"${TLS_KEY}\"},
  {\"op\": \"add\", \"path\": \"/data/openbao.crt\", \"value\": \"${TLS_CRT}\"},
  {\"op\": \"add\", \"path\": \"/data/openbao.ca\",  \"value\": \"${CA_CERT}\"}
]"
```

**Why patch?**
OpenBao expects different key names than cert-manager creates
- cert-manager creates: `tls.key`, `tls.crt`, `ca.crt`
- OpenBao expects: `openbao.key`, `openbao.crt`, `openbao.ca`
- Patch adds the OpenBao-named keys pointing to same data

### Deploy OpenBao

We can now deploy OpenBao via helm as the TLS configuration is ready. The helm
deployment uses the following override values:

**openbao-values-tls.yaml specifies:**
- 3 replicas (HA cluster)
- Raft storage backend (built-in consensus)
- TLS listener on port 8200
- Mounts `openbao-tls` secret into `/openbao/userconfig/openbao-tls/`

**End Result:** 3 OpenBao pods running, but **sealed** (encrypted, can't read/write yet).

## 3.2 Step 03 - Initialize and Unseal OpenBao
- **The Script**: Step-03-OpenBao-Initialize-JoinUnseal.sh
- **What it does:**
Unlocks the encrypted OpenBao cluster and forms a Raft cluster.

**Why Unsealing is Necessary**
OpenBao stores all secrets **encrypted at rest**. The encryption key is split using [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing):

**Master Key (encrypts all data)**
- Split into shares using Shamir's algorithm
- Example: 5 shares created, need any 3 to reconstruct (3-of-5)
- Each operator gets one share
- No single person can unseal alone

**For this prototype**: Using 1-of-1 for simplicity  
**For production**: Use 5-of-3 or similar, distribute shares to different operators

### 3.2.1 Script internal steps to unseal
1. **Wait until openbao-0 pod is ready** wait_for_openbao
2. **Initialize openbao-0** initialize_openbao to allow cluster formation
```
Initialize creates the master key and splits it
bao operator init -key-shares=1 -key-threshold=1
```
```
Output: unseal_keys_b64, root_token → SAVE THESE!
```
```
kubectl exec -n openbao openbao-0 -- bao operator init \
  -key-shares=1 \
  -key-threshold=1 \
  -format=json > cluster-keys.json
As this is a test environment, we are only setting 1 share for operational
simplicity purposes. Obviously something not to do in production. 
```
2. **Unseal openbao** unseal_openbao the first pod
3. **Join other pods to openbao-0** join_openbao_node "openbao-1", join_openbao_node "openbao-2"
```
Builds the openbao raft cluster.
```
4. **Unseal other pods** unseal_openbao_node "openbao-1", unseal_openbao_node "openbao-2"
```
Decrypts OpenBao's storage
Node becomes **active** (can serve requests)
```
5. **Login to Openbao** login_to_openbao - test setup and unsealing
6. **Validate** validate_openbao_setup

**Result:** 3-node HA cluster, all unsealed, leader election active.

**Important**: Save cluster-keys.json Securely
```
This file contains:
    Unseal keys (required after pod restarts)
    Root token (admin access)

In production:
    Store unseal keys in separate secure locations
    Use auto-unseal with cloud KMS
    Rotate root token after initial setup
```

### Final Step - Setup port-forward 
Open a new terminal and run:
   "/bin/bash $PROTODIR/scripts/Helpers/openbao-portforward.sh"

Note - Leave that terminal open while continuing.

## 3.3 Step 04: Configure Secrets and PKI Infrastructure
- **The Script** - Step-04-OpenBao-ConfigureCA.sh
- **What it does:**
Sets up a two-tier Certificate Authority for issuing service certificates.

### 3.3.1 Script process steps
1. **Enable Engines** Enable openbao pki and secrets engines
2. **Setup Admin Policy** Deploy admin policy which allows openbao administration.
```
Admin Policy is defined at ${PROTODIR}/openbao/policy/adminPolicy.hcl
```
3. **Create Admin Token** Create a token which can be used for Openbao login.
4. **Create Root CA** Create the certs, role and default issuers for the Root CA
```
bao_in_pod write -ca-cert="$CA_CERT_PATH" -field=certificate pki/root/generate/internal \
    common_name="Root CA" \
    key_type=rsa \
    key_bits=4096 \
    issuer_name="$NEW_ROOT_NAME" \
    ttl=87600h > "$ROOT_PEM"
```
```
Configure PKI URLs...
bao_in_pod write -ca-cert="$CA_CERT_PATH" pki/config/urls \
    issuing_certificates="$OPENBAO_ADDR/v1/pki/ca" \
    crl_distribution_points="$OPENBAO_ADDR/v1/pki/crl" \
    ocsp_servers="$OPENBAO_ADDR/v1/ocsp"
```
```
Create root PKI role for general server certificates...
bao_in_pod write -ca-cert="$CA_CERT_PATH" pki/roles/2025-servers \
    allow_any_name=true \
    allow_subdomains=true \
    key_type=rsa \
    key_bits=4096 \
    max_ttl="87600h"
```
```
Set the root default issuer
bao_in_pod write -ca-cert="$CA_CERT_PATH" pki/config/issuers default="$ROOT_ISSUER_ID"
```
5. **Enable Nats Intermediate CA** Create the certs, role and default issuers for the Intermediate CA
```
bao_in_pod secrets enable -ca-cert="$CA_CERT_PATH" -path=nats_int pki || echo "nats_int already enabled"
bao_in_pod secrets tune   -ca-cert="$CA_CERT_PATH" -max-lease-ttl=72h nats_int
```
```
**Why two PKIs?**
- `pki`: Root CA, long-lived, signs intermediates
- `nats_int`: Intermediate CA, short-lived, signs service certs
```
```
Generate new Nats intermediate CSR
bao_in_pod write -ca-cert="$CA_CERT_PATH" -format=json nats_int/intermediate/generate/internal \
    common_name="Nats Intermediate Authority" \
    key_type=rsa \
    key_bits=4096 \
    | jq -r '.data.csr' > "$PROTODIR/openbao/gen/csr/nats_intermediate.csr"
```
```
Sign Nats intermediate CA with root certificate"
bao_in_pod write -ca-cert="$CA_CERT_PATH" -format=json pki/root/sign-intermediate \
    csr=- \
    format=pem_bundle \
    ttl="18h" \
    < "$PROTODIR/openbao/gen/csr/nats_intermediate.csr" \
    | jq -r '.data.certificate' > "$PROTODIR/openbao/gen/crypto/nats_ca.crt"
```
```
Set signed certificate for Nats intermediate CA..."
bao_in_pod write -ca-cert="$CA_CERT_PATH" nats_int/intermediate/set-signed certificate=- <<<"$(cat "$PROTODIR/openbao/gen/crypto/nats_ca.crt")"
```
```
Set default issuer for nats_int"
bao_in_pod write -ca-cert="$CA_CERT_PATH" nats_int/config/issuers default="$NATS_ISSUER_ID"
```
```
Configure Nats PKI URLs"
bao_in_pod write -ca-cert="$CA_CERT_PATH" nats_int/config/urls \
    issuing_certificates="$OPENBAO_ADDR/v1/nats_int/ca" \
    crl_distribution_points="$OPENBAO_ADDR/v1/nats_int/crl"
```
6. Create initial Nats CA Bundle for Client validation
```
cat nats_ca.crt root_ca.crt > nats_ca_bundle.pem
```
```
**Why bundle?**
Services need **both** certificates to verify the chain:
Service cert → signed by → Intermediate CA → signed by → Root CA
```
7. Create Kubernetes Secret for CA Bundle
```bash
kubectl create secret generic nats-ca-bundle \
  --from-file=ca-bundle.pem=nats_ca_bundle.pem \
  -n openbao
```
```
**This secret will be:**
- Copied to other clusters
- Used by services to verify NATS certificates
```
8. Create Certificate Role
```
kubectl exec -n openbao openbao-0 -- bao write \
  nats_int/roles/nats-tls-issuer \
  allowed_domains=nats \
  allow_subdomains=true \
  max_ttl=12h
```
```
**What this allows:**
- Issue certificates for `*.nats` domains
- Certificates valid for max 12 hours
```

## 3.4 Step 05: Configure OpenBao Roles and Policies
- **The Script**: Step-05-OpenBao-ConfigureAuthAndIssuers.sh
- **What it does:**
Creates authentication credentials, roles and policies for service to OpenBao.

### 3.4.1 Script process steps
1. **Authenticate to OpenBao** Login with an Admin Token
2. **Enable AppRole Authentication**
```
kubectl exec -n openbao openbao-0 -- bao auth enable approle
```
3. **Create Various Nats Roles and Policies** - Provide Cert-manager access for Nats Certificates
4. **Create Nats AppRole with Policies** 
```
kubectl exec -n openbao openbao-0 -i -- bao write -ca-cert=$CA_CERT_PATH auth/approle/role/nats \
    token_policies="nats-policy,nats-tls-issuer,signing-keys-read" \
    token_ttl=1d \
    token_max_ttl=1d \
    bind_secret_id=true \
    secret_id_ttl=12h \
    secret_id_num_uses=0
```
5. **Create Metadata Service Roles and Policies** 
6. **Create Metadata Service AppRole with Policies**
```
Creating AppRole: metadata"
kubectl exec -n openbao openbao-0 -i -- bao write -ca-cert=$CA_CERT_PATH auth/approle/role/metadata \
    token_policies="metadata-policy,metadata-tls-issuer,signing-keys-read,metadata-signing-keys-write,metadata-pki-admin,nats-ca-admin" \
    token_ttl=1d \
    token_max_ttl=1d \
    bind_secret_id=true \
    secret_id_ttl=12h \
    secret_id_num_uses=0
```
7. **Create Watcher Service Roles and Policies** 
8. **Create Watcher Service AppRole with Policies**
```
Creating AppRole: watcher"
kubectl exec -n openbao openbao-0 -i -- bao write -ca-cert=$CA_CERT_PATH auth/approle/role/watcher \
    token_policies="watcher-policy,watcher-tls-issuer,signing-keys-read,watcher-signing-keys-write" \
    token_ttl=1d \
    token_max_ttl=1d \
    bind_secret_id=true \
    secret_id_ttl=12h \
    secret_id_num_uses=0

```

# 4.0 Step 06: Deploy NATS to Servers Cluster
- **The Script**: Step-06-DeployNatsToServers.sh
- **What it does:**
Deploys NATS JetStream with TLS certificates from OpenBao.

### 4.1 Script process steps
1. **Obtain CA Bundle**
2. **Obtain Nats AppRole roleId and secret**
3. **Create Nats Approle Secret** - nats-bao-approle
4. **Create Nats CA Bundle Secret** - nats-ca-tls
5. **Create Nats TLS Issuer and Certificate**
6. **Create Nats configmap for Nats Internal configuration**
7. **Deploy Nats Statefulset and Services**
8. **Create and Deploy a Maintenance Pod**
9. **Generate the Jetstream streams**
```
KEY_EXCHANGE, METADATA_CA_CLIENT, AUTH_STREAM, GATEKEEPER_STREAM
```
10. **Generate the Pull Consumers**
```
add_pull_consumer "KEY_EXCHANGE" "metadata-key-exchange-metadata"       "metadata.key-exchange.metadata"
add_pull_consumer "KEY_EXCHANGE" "metadata-key-exchange-watcher"        "metadata.key-exchange.watcher"
add_pull_consumer "KEY_EXCHANGE" "metadata-key-exchange-authcontroller" "metadata.key-exchange.authcontroller"
add_pull_consumer "KEY_EXCHANGE" "metadata-key-exchange-gatekeeper"     "metadata.key-exchange.gatekeeper"
```
```
add_pull_consumer "METADATA_CA_CLIENT" "authcontroller-ca-consumer" "metadata.client.ca-cert"
add_pull_consumer "METADATA_CA_CLIENT" "gatekeeper-ca-consumer" "metadata.client.ca-cert"
add_pull_consumer "METADATA_CA_CLIENT" "watcher-ca-consumer" "metadata.client.ca-cert"
```
```
add_pull_consumer "AUTH_STREAM" "auth-requests" "auth.auth-request"
add_pull_consumer "AUTH_STREAM" "auth-tester-consumer" "auth.tester.consumer"
```
```
add_pull_consumer "GATEKEEPER_STREAM" "gatekeeper-responder-consumer" "gatekeeper.responder"
```
11. **Manually start a port forward in another terminal**
```
/bin/bash $PROTODIR/scripts/Helpers/Nats-portforward.sh"
```

## 5.0 Step 07: Deploy Metadata Service to Bao Cluster
- **The Script**: Step-07-DeployMetadataSvcToBaoCluster.sh
- **What it does:**
Deploys the metadata service.
```
Metadata Service (The Authority)

Maintains authorization matrix defining service-to-service communication
Generates and signs ServiceBundles for all services defining and implementing service permissions.
Creates topic encryption keys with embedded permissions-
Publishes Intermediate CA certificate bundles
The brain of the security infrastructure
Detailed in Blog 3 & 4
```

### 5.1 Script process steps

1. **Get Metadata AppRole Credentials**
2. **Create Metadata AppRole Secret** metadata-bao-approle
3. **Create Nats CA Bundle Secret** nats-ca-secret
4. **Create OpenBao CA Bundle Secret** openbao-ca-secret
5. **Generate Metadata TLS Issuer**
6. **Generate Metadata configmap**
7. **Build Metadata Service Docker Image**
8. **Create the Avro Schema configmap**
9. **Apply the various metadata kube manifest files**
10. **Configure namespaces for istio ambient mode mTls**


## 6.0 Steps 08-10: Deploy Watcher, Auth, Gatekeeper

**Same pattern as Metadata Service - Step-07**
Just be sure to be in the right cluster profile.

### 5.1 Script process steps

1. **Get AppRole Credentials**
2. **Create AppRole Secret** metadata-bao-approle
3. **Create Nats CA Bundle Secret** nats-ca-secret
4. **Create OpenBao CA Bundle Secret** openbao-ca-secret
5. **Generate Service TLS Issuer**
6. **Build Service Docker Image**
7. **Build the Avro Schema configmap**
9. **Apply the various service kube manifest files**
10. **Configure namespace(s) for istio ambient mode mTls**

## 7.0 Summary: What Each Step Actually Does

| Step | Cluster | Action | Result |
|------|---------|--------|--------|
| 01a | bao | Create cluster | Empty k8s cluster with cert-manager |
| 01b | servers | Create cluster | Empty k8s cluster with cert-manager |
| 01c | services | Create cluster | Empty k8s cluster with cert-manager |
| 02 | bao | Install OpenBao | 3 sealed Vault pods |
| 03 | bao | Unseal OpenBao | 3 active Vault nodes in Raft cluster |
| 04 | bao | Configure PKI | Root CA + NATS intermediate CA ready |
| 05 | bao | Create AppRoles & Policies | NATS, Metadata, Watcher, Auth, Gatekeeper credentials |
| 06 | servers | Deploy NATS | 3-node JetStream cluster with auto-renewing certs |
| 07 | bao | Deploy Metadata | Service connecting to NATS in servers cluster |
| 08 | servers | Deploy Watcher | Service monitoring cert health |
| 09 | services | Deploy Auth | Authentication service |
| 10 | services | Deploy Gatekeeper | API gateway service |

---

## 8.0 Troubleshooting

### 8.1 Common Issues

#### Minikube Won't Start
```
# Error: "Exiting due to RSRC_INSUFFICIENT_CORES"
# Solution: Reduce CPU allocation
minikube start -p bao --cpus 2 --memory 4096
```
```
# Error: "permission denied" with Docker
# Solution: Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```
```
# Check cert-manager logs
kubectl logs -n cert-manager -l app=cert-manager --tail=50

# Common cause: Certificate not ready
kubectl describe certificate -n openbao openbao-tls

# Fix: Delete and recreate certificate
kubectl delete certificate -n openbao openbao-tls
kubectl apply -f $PROTODIR/openbao/kube/openbao-certs.yaml
```
```
# This is NORMAL - pods seal on restart
# Solution: Unseal each pod
UNSEAL_KEY=$(jq -r ".unseal_keys_b64[]" cluster-keys.json)
for pod in openbao-0 openbao-1 openbao-2; do
  kubectl exec -n openbao $pod -- bao operator unseal $UNSEAL_KEY
done
```

