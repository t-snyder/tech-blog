---
layout: readme
title: Secure Transport Research Project - Part 5 - OpenBao Integration via Agent Sidecar
exclude_from_feed: true
pinned: false
excerpt: "Deep dive into OpenBao integration: AppRole authentication with Agent sidecar, automatic token management, cert-manager TLS certificate issuance, secret storage and retrieval, and automatic secret-id rotation. Explores the complete lifecycle from Kubernetes configuration to application-level vault access."
categories: [Security, Cryptography, Kubernetes]
tags: [openbao, vault, approle, cert-manager, kubernetes, secrets-management, pki, tls]
series: "SecureTransport Research Prototype"
series_part: 5
---

# OpenBao Integration via Agent Sidecar: Secrets Management and PKI

## Introduction

In traditional Kubernetes deployments, secrets management is often handled through Kubernetes Secrets, which have significant limitations:

1. **No rotation mechanism** - Secrets remain static until manually updated
2. **Limited encryption** - Secrets are base64-encoded, not encrypted at rest (unless etcd encryption is enabled)
3. **No centralized audit** - No built-in audit trail for secret access
4. **No fine-grained permissions** - RBAC is coarse-grained at the namespace level
5. **No dynamic certificate generation** - TLS certificates must be manually created and rotated

SecureTransport solves these problems by integrating **OpenBao** (HashiCorp Vault open-source fork) with a **sidecar Agent pattern**:

- ✅ **Automatic token management** - Agent handles authentication and token renewal
- ✅ **Dynamic secrets** - Secrets can be generated on-demand with TTLs
- ✅ **PKI integration** - Certificates issued dynamically via cert-manager
- ✅ **Automatic rotation** - AppRole secret-id rotated every 5 minutes
- ✅ **Fine-grained permissions** - Policy-based access control per service
- ✅ **Audit logging** - All secret access logged in OpenBao
- ✅ **Zero-trust** - Services never handle long-lived credentials

This blog explores the complete OpenBao integration lifecycle: AppRole configuration, Agent sidecar setup, cert-manager integration, automatic secret-id rotation, and application-level vault access.

---

## 1. OpenBao Architecture Overview

### 1.1 The Agent Sidecar Pattern

```
┌──────────────────────────────────────────────────────────────┐
│                  OpenBao Integration Architecture            │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ Kubernetes Pod: metadata                                     │
│                                                              │
│  ┌─────────────────────────┐  ┌──────────────────────────┐   │
│  │ Container: bao-agent    │  │ Container: metadata      │   │
│  │                         │  │                          │   │
│  │ • Auto-auth (AppRole)   │  │ • Reads token from file  │   │
│  │ • Token renewal         │  │ • API calls via Agent    │   │
│  │ • Caching               │  │ • No direct vault auth   │   │
│  │ • Local API proxy       │  │                          │   │
│  │   (localhost:8100)      │  │                          │   │
│  └─────────────────────────┘  └──────────────────────────┘   │
│          │                              │                    │
│          │ Shares PVC:                  │                    │
│          │ /home/bao/token              │                    │
│          └──────────────────────────────┘                    │
│                                                              │
│  Volumes:                                                    │
│  • bao-agent-token (PVC)        - Shared token file          │
│  • bao-approle (Secret)         - role-id + secret-id        │
│  • openbao-ca (Secret)          - CA certificate             │
│  • bao-agent-config (ConfigMap) - Agent configuration        │
└──────────────────────────────────────────────────────────────┘
                              │
                              │ TLS (mTLS via Istio Gateway)
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ OpenBao Server (openbao.openbao.svc.cluster.local:8200)      │
│                                                              │
│ • AppRole authentication                                     │
│ • KV secrets engine (service-bundles, ca-bundles)            │
│ • PKI engines (Root CA, Intermediate CA)                     │
│ • Policy-based access control                                │
│ • Audit logging                                              │
└──────────────────────────────────────────────────────────────┘
                              │
                              │ cert-manager integration
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ cert-manager (TLS Certificate Management)                    │
│                                                              │
│ • Reads AppRole credentials from Secret                      │
│ • Authenticates to OpenBao                                   │
│ • Requests certificate signing                               │
│ • Stores certificate in Kubernetes Secret                    │
│ • Auto-renewal before expiration                             │
└──────────────────────────────────────────────────────────────┘
```

### 1.2 Key Components

**OpenBao Agent Sidecar:**
- Handles AppRole authentication using role-id and secret-id
- Automatically renews Vault tokens before expiration
- Writes token to shared volume (`/home/bao/token`)
- Provides local API proxy on `localhost:8100`
- Caches secrets for performance

**Metadata Service Container:**
- Reads token from shared file
- Makes API calls via Agent's local proxy
- Never handles AppRole credentials directly
- Uses `MetadataVaultHandler` which calls `VaultAccessHandler` for all Vault operations

**VaultAppRoleSecretRotationVert:**
- Rotates AppRole secret-id every 5 minutes
- Updates Kubernetes Secret with new secret-id
- Ensures Agent picks up new secret-id automatically
- Prevents secret-id expiration (12-hour TTL)

**cert-manager:**
- Uses same AppRole credentials for PKI operations
- Issues TLS certificates from OpenBao PKI engine
- Automatically renews certificates before expiration
- Stores certificates in Kubernetes Secrets

---

## 2. OpenBao Configuration and Permissions

### 2.1 AppRole Setup for Metadata Service

From `Step-05-OpenBao-ConfigureAuthAndIssuers.sh`:

```bash
#!/bin/bash
# OpenBao AppRole Authentication Setup Script

set -e

PROTODIR=/media/tim/ExtraDrive1/Projects/010-SecureTransport/deploy
CA_CERT_PATH="/openbao/userconfig/openbao-tls/openbao.ca"

# Wait for OpenBao to be ready
wait_for_openbao() {
    echo "Waiting for OpenBao to be ready..."
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        echo "Attempt $attempt of $max_attempts: Checking OpenBao status..."
        if kubectl exec -n openbao openbao-0 -- bao status -ca-cert=$CA_CERT_PATH > /dev/null 2>&1; then
            echo "OpenBao is ready!"
            return 0
        else
            echo "OpenBao not ready yet, waiting 10 seconds..."
            sleep 10
            ((attempt++))
        fi
    done
    echo "OpenBao did not become ready within the expected time"
    return 1
}

wait_for_openbao

# Authenticate with root token
ROOT_TOKEN=$(jq -r .root_token $PROTODIR/openbao/gen/crypto/cluster-keys.json)
kubectl exec -n openbao openbao-0 -- bao login -ca-cert=$CA_CERT_PATH $ROOT_TOKEN

# Create admin token for operations
echo "Creating new ADMIN_TOKEN..."
kubectl exec -n openbao openbao-0 -- \
  bao token create -ca-cert=$CA_CERT_PATH -format=json -policy="admin" \
  > $PROTODIR/openbao/gen/crypto/admin_token.json

ADMIN_TOKEN=$(jq -r ".auth.client_token" $PROTODIR/openbao/gen/crypto/admin_token.json)

# Re-authenticate with admin token
kubectl exec -n openbao openbao-0 -- bao login -ca-cert=$CA_CERT_PATH $ADMIN_TOKEN

# Enable AppRole authentication
echo "Enabling approle authentication..."
kubectl exec -n openbao openbao-0 -- \
  bao auth enable -ca-cert=$CA_CERT_PATH approle 2>/dev/null || \
  echo "AppRole auth method already enabled"

# Enable KV secrets engine
echo "Creating KV secrets engine path for signing keys..."
kubectl exec -n openbao openbao-0 -- \
  bao secrets list -ca-cert=$CA_CERT_PATH | grep -q "secret/" || \
  kubectl exec -n openbao openbao-0 -- \
    bao secrets enable -ca-cert=$CA_CERT_PATH -path=secret kv-v2
```

### 2.2 Metadata Service Policies
From `Step-05-OpenBao-ConfigureAuthAndIssuers.sh`:

```bash
# Create comprehensive policy for metadata service
echo "Creating policy: metadata-policy"
kubectl exec -n openbao openbao-0 -i -- \
  bao policy write -ca-cert=$CA_CERT_PATH metadata-policy - <<EOF

# Basic metadata secrets access
path "secret/data/metadata/*" {
  capabilities = ["read"]
}

# Token management
path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# AppRole secret-id rotation
path "auth/approle/role/metadata/secret-id" {
  capabilities = ["update", "create"]
}

# NATS CA chain read access
path "nats_int/ca_chain" {
  capabilities = ["read"]
}

# === CA ROTATION PERMISSIONS ===

# PKI Issuer Management
path "nats_int/issuer/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "nats_int/issuers" {
  capabilities = ["list", "read"]
}

# PKI Key Management
path "nats_int/key/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "nats_int/keys" {
  capabilities = ["list", "read"]
}

# Generate new keys
path "nats_int/keys/generate/internal" {
  capabilities = ["create", "update"]
}

# Intermediate CA generation
path "nats_int/intermediate/generate/internal" {
  capabilities = ["create", "update"]
}

# Import signed certificates
path "nats_int/intermediate/set-signed" {
  capabilities = ["create", "update"]
}

# Import certificate bundles
path "nats_int/issuers/import/cert" {
  capabilities = ["create", "update"]
}

# Root CA signing (for intermediate certs)
path "pki/root/sign-intermediate" {
  capabilities = ["create", "update"]
}

# PKI configuration
path "nats_int/config/issuers" {
  capabilities = ["read", "update"]
}

path "nats_int/config/keys" {
  capabilities = ["read", "update"]
}

# Read root CA for signing
path "pki/cert/ca" {
  capabilities = ["read"]
}

path "pki/ca_chain" {
  capabilities = ["read"]
}

# === END CA ROTATION PERMISSIONS ===

# Service bundles storage
path "secret/data/service-bundles/*" {
  capabilities = ["create", "update", "read", "list"]
}

path "secret/metadata/service-bundles/*" {
  capabilities = ["read", "list", "delete"]
}

# CA bundles storage
path "secret/data/ca-bundles/*" {
  capabilities = ["create", "update", "read", "list"]
}

path "secret/metadata/ca-bundles/*" {
  capabilities = ["read", "list", "delete"]
}
EOF
```

### 2.3 TLS Issuer Policy
From `Step-05-OpenBao-ConfigureAuthAndIssuers.sh`:

```bash
# Create policy for TLS certificate issuance
echo "Creating metadata-tls-issuer policy..."
kubectl exec -n openbao openbao-0 -i -- \
  bao policy write -ca-cert=$CA_CERT_PATH metadata-tls-issuer - <<EOF

path "nats_int/roles/metadata-tls-issuer" {
  capabilities = ["read", "list", "create", "update"]
}

path "nats_int/sign/metadata-tls-issuer" {
  capabilities = ["create", "update"]
}

path "nats_int/issue/metadata-tls-issuer" {
  capabilities = ["create"]
}

path "nats_int/cert/ca" {
  capabilities = ["read"]
}

path "nats_int/ca_chain" {
  capabilities = ["read"]
}

path "nats_int/crl" {
  capabilities = ["read"]
}
EOF
```

### 2.4 Create AppRole with Combined Policies
Once the policies are in place they can be used to generate the AppRole

```bash
# Create TLS issuer role in PKI engine
echo "Creating metadata-tls-issuer role..."
kubectl exec -n openbao openbao-0 -i -- \
  bao write -ca-cert=$CA_CERT_PATH nats_int/roles/metadata-tls-issuer \
    allowed_domains=metadata.nats \
    allow_subdomains=true \
    allow_bare_domains=true \
    allow_any_name=true \
    max_ttl=12h \
    key_type=rsa \
    key_bits=4096

# Create AppRole with all required policies
echo "Creating AppRole: metadata"
kubectl exec -n openbao openbao-0 -i -- \
  bao write -ca-cert=$CA_CERT_PATH auth/approle/role/metadata \
    token_policies="metadata-policy,metadata-tls-issuer,signing-keys-read,metadata-signing-keys-write,nats-ca-admin" \
    token_ttl=1d \
    token_max_ttl=1d \
    bind_secret_id=true \
    secret_id_ttl=12h \
    secret_id_num_uses=0

# Get role-id (static)
kubectl exec -n openbao openbao-0 -- \
  bao read -ca-cert=$CA_CERT_PATH -format=json auth/approle/role/metadata/role-id \
  | jq -r '.data.role_id'

# Output: 999315e2-318e-5380-3a7f-a3ed3c7ed812

# Generate initial secret-id (will be rotated)
kubectl exec -n openbao openbao-0 -- \
  bao write -ca-cert=$CA_CERT_PATH -format=json auth/approle/role/metadata/secret-id \
  | jq -r '.data.secret_id'

# Output: <initial-secret-id>
```

**Key Configuration Points:**

- **token_ttl**: 1 day (Agent renews automatically)
- **token_max_ttl**: 1 day maximum
- **secret_id_ttl**: 12 hours (rotated every 5 minutes to prevent expiration)
- **secret_id_num_uses**: 0 (unlimited uses)
- **bind_secret_id**: true (requires both role-id and secret-id)

---

## 3. Kubernetes Configuration

### 3.1 AppRole Credentials Secret

```yaml
# Created manually with initial credentials
apiVersion: v1
kind: Secret
metadata:
  name: metadata-bao-approle
  namespace: metadata
type: Opaque
data:
  role-id: OTk5MzE1ZTItMzE4ZS01MzgwLTNhN2YtYTNlZDNjN2VkODEy  # base64: 999315e2-318e-5380-3a7f-a3ed3c7ed812
  secret-id: <base64-encoded-initial-secret-id>
```

**Note:** The `secret-id` in this Secret is updated every 5 minutes by `VaultAppRoleSecretRotationVert`.

### 3.2 OpenBao Agent ConfigMap

From `bao-agent-configmap.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: bao-agent-config
  namespace: metadata
data:
  agent.hcl: |
    ## Agent-wide settings
    exit_after_auth = false
    pid_file = "/home/bao/pidfile"

    ## Vault server connection (via TLS)
    vault {
      address = "https://openbao.openbao.svc.cluster.local:8200"
      
      # Trust the cert-manager generated CA
      tls_ca_file = "/etc/bao/ca/ca.crt"
      
      # Skip hostname verification (accessing via cluster DNS)
      tls_skip_verify = true
      
      # Retry configuration
      retry {
        num_retries = 5
        initial_backoff = "5s"
        max_backoff = "30s"
      }
    }

    ## AppRole authentication
    auto_auth {
      method "approle" {
        mount_path = "auth/approle"
        config = {
          role_id_file_path = "/etc/bao/role-id"
          secret_id_file_path = "/etc/bao/secret-id"
          remove_secret_id_file_after_reading = false
          secret_id_refresh_interval = "10s"  # Check for new secret-id every 10 seconds
        }
      }

      ## Write token to shared file
      sink "file" {
        config = {
          path = "/home/bao/token"
          mode = 0640
        }
      }
    }

    ## Enable caching for performance
    cache {
      persist = {
        type = "kubernetes"
        path = "/home/bao/cache"
      }
    }

    ## Local API proxy (metadata service connects here)
    listener "tcp" {
      address = "0.0.0.0:8100"
      tls_disable = true
    }
    
    ## API proxy uses auto-auth token
    api_proxy {
      use_auto_auth_token = true
    }

    ## Logging
    log_level = "info"
    log_format = "json"
```

**Key Configuration:**

- **secret_id_refresh_interval**: Agent checks for new secret-id every 10 seconds
- **remove_secret_id_file_after_reading**: `false` (allows rotation without restart)
- **sink "file"**: Writes token to shared PVC at `/home/bao/token`
- **listener "tcp"**: Local proxy on `localhost:8100` for metadata service
- **api_proxy**: Automatically includes token in all requests

### 3.3 Metadata Deployment with Sidecar

From `metadata-deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: metadata
  namespace: metadata
spec:
  replicas: 1
  selector:
    matchLabels:
      app: metadata
  template:
    metadata:
      labels:
        app: metadata
    spec:
      serviceAccountName: metadata-sa

      ## Shared volumes
      volumes:
      # AppRole credentials (role-id + secret-id)
      - name: bao-approle
        projected:
          sources:
          - secret:
              name: metadata-bao-approle
              items:
              - key: role-id
                path: role-id
              - key: secret-id
                path: secret-id
      
      # OpenBao CA certificate
      - name: openbao-ca
        projected:
          sources:
          - secret:
              name: openbao-ca-secret
              items:
              - key: ca.crt
                path: ca.crt
      
      # Agent configuration
      - name: bao-agent-config
        configMap:
          name: bao-agent-config
          items:
          - key: agent.hcl
            path: agent.hcl
      
      # Shared token file (PVC)
      - name: bao-agent-token
        persistentVolumeClaim:
          claimName: bao-agent-token-pvc
      
      # Agent cache
      - name: bao-agent-cache
        emptyDir:
          sizeLimit: "50Mi"
      
      # ... other volumes (NATS certs, etc.)

      containers:
      ## OpenBao Agent Sidecar
      - name: bao-agent
        image: openbao/openbao:latest
        imagePullPolicy: IfNotPresent
        securityContext:
          runAsUser: 1000
          runAsGroup: 1000
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
        
        volumeMounts:
        - name: bao-approle
          mountPath: /etc/bao
          readOnly: true
        - name: bao-agent-config
          mountPath: /etc/bao-agent
          readOnly: true
        - name: openbao-ca
          mountPath: /etc/bao/ca
          readOnly: true
        - name: bao-agent-token
          mountPath: /home/bao
        - name: bao-agent-cache
          mountPath: /home/bao/cache
        
        command: ["bao", "agent", "-config=/etc/bao-agent/agent.hcl"]
        
        env:
        - name: VAULT_LOG_LEVEL
          value: "info"
      
      ## Metadata Service Container
      - name: metadata
        image: library/metadatasvc:1.0
        imagePullPolicy: IfNotPresent
        securityContext:
          runAsUser: 1000
          runAsGroup: 1000
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
        
        ports:
        - containerPort: 8080
          name: http
        
        env:
        - name: CONFIG_MAP_NAME
          value: metadata-configmap
        
        volumeMounts:
        - name: metadata-config
          mountPath: /app/config
          readOnly: true
        - name: bao-agent-token
          mountPath: /home/bao  # Shared with Agent
        # ... other mounts
```

**Volume Sharing:**

The `bao-agent-token` PVC is mounted in **both containers**:
- **bao-agent**: Writes token to `/home/bao/token`
- **metadata**: Reads token from `/home/bao/token`

This eliminates the need for metadata service to handle AppRole authentication.

---

## 4. Automatic Secret-ID Rotation

### 4.1 VaultAppRoleSecretRotationVert

From `VaultAppRoleSecretRotationVert.java`:

```java
Project: svc-core
Package: core.verticle
Class:   VaultAppRoleSecretRotationVert.java

/**
 * This verticle rotates the 'secret-id' for an OpenBao AppRole by updating
 * the appropriate Kubernetes Secret. It requests a new secret-id from OpenBao
 * at startup and on a periodic interval, patches the K8s Secret, and works
 * seamlessly with Vault Agent that reads secret-id from a mounted file.
 */
public class VaultAppRoleSecretRotationVert extends AbstractVerticle {
  
  private static final Logger LOGGER = LoggerFactory.getLogger(VaultAppRoleSecretRotationVert.class);
  
  private final KubernetesClient kubeClient;
  private final String namespace;
  private final String secretName;           // "metadata-bao-approle"
  private final String vaultRoleName;        // "metadata"
  private final long rotationIntervalMs;     // 300000 (5 minutes)
  
  private VaultAccessHandler vaultAccessHandler;
  private WorkerExecutor workerExecutor;
  
  public VaultAppRoleSecretRotationVert(KubernetesClient kubeClient,
                                       String namespace,
                                       String secretName,
                                       String vaultRoleName,
                                       long rotationIntervalMs,
                                       VaultAccessHandler vaultAccessHandler) {
    this.kubeClient = kubeClient;
    this.namespace = namespace;
    this.secretName = secretName;
    this.vaultRoleName = vaultRoleName;
    this.rotationIntervalMs = rotationIntervalMs;
    this.vaultAccessHandler = vaultAccessHandler;
  }
  
  @Override
  public void start(Promise<Void> startPromise) {
    LOGGER.info("VaultAppRoleSecretRotationVert started for secret: {} with vault role: {}", 
                secretName, vaultRoleName);
    
    this.workerExecutor = vertx.createSharedWorkerExecutor("approle-worker", 2, 360000);
    
    // Generate new secret-id and update K8s Secret at startup
    rotateSecretIdAsync();
    
    // Schedule periodic rotation every 5 minutes
    vertx.setPeriodic(rotationIntervalMs, id -> rotateSecretIdAsync());
    
    startPromise.complete();
  }
  
  /**
   * Asynchronously rotates the secret-id:
   * 1. Reads current role-id from K8s Secret
   * 2. Requests new secret-id from Vault Agent API
   * 3. Patches the K8s Secret with new secret-id
   */
  private void rotateSecretIdAsync() {
    LOGGER.info("Checking for secret_id update for role: {}", vaultRoleName);
    
    workerExecutor.executeBlocking(() -> {
      try {
        // Step 1: Get current role_id from the Secret
        Secret k8sSecret = kubeClient.secrets()
          .inNamespace(namespace)
          .withName(secretName)
          .get();
        
        if (k8sSecret == null || k8sSecret.getData() == null) {
          String errMsg = "Kubernetes Secret " + secretName + " not found in namespace " + namespace;
          LOGGER.error(errMsg);
          throw new Exception(errMsg);
        }
        
        String roleId = B64Handler.decodeB64(k8sSecret.getData().get("role-id"));
        if (roleId == null) {
          String errMsg = "role-id not found in K8s Secret " + secretName;
          LOGGER.error(errMsg);
          throw new Exception(errMsg);
        }
        
        // Step 2: Get Vault token using handler
        vaultAccessHandler.getVaultToken()
          .onSuccess(token -> {
            
            // Step 3: Request new secret-id via handler
            vaultAccessHandler.requestNewSecretId(vaultRoleName, token)
              .onSuccess(newSecretId -> {
                if (newSecretId != null) {
                  updateK8sSecretWithNewSecretId(k8sSecret, newSecretId);
                } else {
                  LOGGER.error("Received null secret-id from Vault for role {}", vaultRoleName);
                }
              })
              .onFailure(e -> {
                LOGGER.error("Failed to rotate secret-id: {}", e.getMessage(), e);
              });
          })
          .onFailure(err -> {
            LOGGER.error("Failed to get Vault token: {}", err.getMessage(), err);
          });
          
      } catch (Exception e) {
        String errMsg = "Error during secret-id rotation: " + e.getMessage();
        LOGGER.error(errMsg);
        return ServiceCoreIF.FAILURE;
      }
      
      return ServiceCoreIF.SUCCESS;
    });
  }
  
  /**
   * Updates the K8s Secret with the new base64-encoded secret-id.
   */
  private void updateK8sSecretWithNewSecretId(Secret k8sSecret, String newSecretId) {
    try {
      Map<String, String> data = k8sSecret.getData();
      data.put("secret-id", B64Handler.encodeB64(newSecretId));
      
      kubeClient.secrets()
        .inNamespace(namespace)
        .withName(secretName)
        .edit(s -> {
          s.setData(data);
          return s;
        });
      
      LOGGER.info("✅ Updated secret_id for role {} in Secret {}", vaultRoleName, secretName);
    } catch (Exception e) {
      String errMsg = "Failed to update K8s Secret: " + secretName + "; Error = " + e.getMessage();
      LOGGER.error(errMsg);
    }
  }
}
```

**Rotation Flow:**

```
Timeline: Secret-ID Rotation Cycle (Every 5 minutes)
-----------------------------------------------------

T=00:00:00 - VaultAppRoleSecretRotationVert starts
             - Initial secret-id rotation
             - Kubernetes Secret updated

T=00:00:05 - OpenBao Agent detects new secret-id
             - secret_id_refresh_interval = 10s
             - Agent re-authenticates with new secret-id
             - New token issued (TTL: 1 day)
             - Token written to /home/bao/token

T=00:05:00 - Periodic rotation triggered (rotationIntervalMs = 300000)
             - VaultAccessHandler.getVaultToken() reads current token
             - VaultAccessHandler.requestNewSecretId() called
             - OpenBao generates new secret-id
             - Kubernetes Secret updated

T=00:05:10 - Agent detects updated secret-id
             - Re-authenticates automatically
             - No service restart required

T=00:10:00 - Next rotation cycle...

Advantage: secret-id TTL is 12 hours, but rotated every 5 minutes
           - 144 rotations per 12-hour period
           - Prevents secret-id expiration
           - Minimal exposure window (5 minutes)
```

### 4.2 VaultAccessHandler - Token and Secret-ID Management

From `VaultAccessHandler.java`:

```java
Project: svc-core
Package: core.handler
Class:   VaultAccessHandler.java

/**
 * VaultAccessHandler - Handles all OpenBao API interactions.
 * 
 * Key responsibilities:
 * - Read Vault token from Agent-rendered file
 * - Request new secret-id for AppRole rotation
 * - Generic Vault API requests (GET, POST, LIST, DELETE)
 * - ServiceBundle and CaBundle retrieval
 */
public class VaultAccessHandler implements AutoCloseable {
  
  private static final Logger LOGGER = LoggerFactory.getLogger(VaultAccessHandler.class);
  
  private static final String SERVICE_BUNDLE_VAULT_MOUNT = "secret";
  private static final String SERVICE_BUNDLE_VAULT_PATH_PREFIX = "service-bundles";
  private static final String CA_BUNDLE_VAULT_PATH_PREFIX = "ca-bundles";
  
  private static final int DEFAULT_CONNECT_TIMEOUT = 10000;
  private static final int DEFAULT_IDLE_TIMEOUT = 10000;
  
  private final Vertx vertx;
  private final WebClient webClient;
  private final String vaultAgentAddr;      // "http://127.0.0.1:8100"
  private final String vaultAgentHost;      // "127.0.0.1"
  private final int vaultAgentPort;         // 8100
  private final String vaultTokenPath;      // "/home/bao/token"
  
  private final WorkerExecutor vaultWorker;
  
  public VaultAccessHandler(Vertx vertx, String serviceId, String vaultAgentAddr,
                           String vaultAgentHost, int vaultAgentPort, String tokenPath) {
    this.vertx = vertx;
    this.vaultAgentAddr = vaultAgentAddr;
    this.vaultAgentHost = vaultAgentHost;
    this.vaultAgentPort = vaultAgentPort;
    this.vaultTokenPath = tokenPath;
    
    WebClientOptions options = new WebClientOptions()
      .setConnectTimeout(DEFAULT_CONNECT_TIMEOUT)
      .setIdleTimeout(DEFAULT_IDLE_TIMEOUT)
      .setDefaultHost(vaultAgentHost)
      .setDefaultPort(vaultAgentPort);
    
    this.webClient = WebClient.create(vertx, options);
    
    // 10 threads, 5-minute max execution
    this.vaultWorker = this.vertx.createSharedWorkerExecutor("vault-worker", 10, 300000);
  }
  
  /**
   * Reads Vault token from the agent-rendered file.
   * 
   * This is called by VaultAppRoleSecretRotationVert and other components
   * that need to make authenticated requests to Vault.
   */
  public Future<String> getVaultToken() {
    Promise<String> promise = Promise.promise();
    
    vaultWorker.executeBlocking(() -> {
      try {
        String token = Files.readString(Paths.get(vaultTokenPath)).trim();
        if (token == null || token.isEmpty()) {
          throw new Exception("Vault token not found at: " + vaultTokenPath);
        }
        return token;
      } catch (Exception e) {
        LOGGER.error("Vault token read failed", e);
        throw new RuntimeException(e);
      }
    }).onComplete(ar -> {
      if (ar.succeeded()) {
        promise.complete((String) ar.result());
      } else {
        promise.fail(ar.cause());
      }
    });
    
    return promise.future();
  }
  
  /**
   * Request new secret-id for AppRole authentication.
   * 
   * Called by VaultAppRoleSecretRotationVert every 5 minutes.
   * 
   * @param vaultRoleName - AppRole name (e.g., "metadata")
   * @param token - Vault token (from getVaultToken())
   * @return Future<String> - New secret-id
   */
  public Future<String> requestNewSecretId(String vaultRoleName, String token) {
    Promise<String> promise = Promise.promise();
    
    String apiUrl = "/v1/auth/approle/role/" + vaultRoleName + "/secret-id";
    
    webClient.post(vaultAgentPort, vaultAgentHost, apiUrl)
      .putHeader("X-Vault-Token", token)
      .putHeader("Content-Type", "application/json")
      .as(BodyCodec.string())
      .sendJsonObject(new JsonObject())
      .onSuccess(response -> {
        if (response.statusCode() != 200) {
          LOGGER.error("Failed to get new secret_id from Vault (code={}): {}", 
                      response.statusCode(), response.body());
          promise.fail("Vault Agent returned non-200 status");
        } else {
          try {
            JsonObject body = new JsonObject(response.body());
            String secretId = body.getJsonObject("data").getString("secret_id");
            
            LOGGER.info("✅ Obtained new secret_id from Vault for role {}", vaultRoleName);
            promise.complete(secretId);
          } catch (Exception e) {
            LOGGER.error("Failed to parse Vault response: {}", e.getMessage());
            promise.fail(e);
          }
        }
      })
      .onFailure(err -> {
        LOGGER.error("Failed to call Vault Agent for secret-id: {}", err.getMessage());
        promise.fail(err);
      });
    
    return promise.future();
  }
  
  // ... (continued in next section)
}
```

---

## 5. cert-manager Integration

### 5.1 Issuer Configuration
The deployment script Step-07-DeployMetadataSvcToBaoCluster creates the metadata-tls-issuer.yaml file
so that it can include string substitution for the server address and CA Bundle.

From the Step-07.. script
```
# Generate metadata-tls-issuer.yaml - now saved to file
cat > "$DEPLOYDIR/metadata-tls-issuer.yaml" <<EOF
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: metadata-tls-issuer
  namespace: $NAMESPACE
spec:
  vault:
    path: nats_int/sign/metadata-tls-issuer
    server: $BAO_ADDR
    caBundle: $BAO_CA_BUNDLE_B64
    auth:
      appRole:
        path: approle
        roleId: $ROLE_ID
        secretRef:
          name: metadata-bao-approle
          key: secret-id
EOF
```

The result which is deployed later is `metadata-tls-issuer.yaml`:

```
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: metadata-tls-issuer
  namespace: metadata
spec:
  vault:
    # PKI signing endpoint in OpenBao
    path: nats_int/sign/metadata-tls-issuer
    
    # OpenBao server address
    server: https://openbao.openbao.svc.cluster.local:8200
    
    # CA certificate (base64-encoded PEM)
    caBundle: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZRekNDQXl1Z0F3SUJBZ0lSQU5wemZuSThvNjNId1NuSWJIcWFmT1l3RFFZSktvWklodmNOQVFFTkJRQXcKT3pFUE1BMEdBMVVFQ2hNR1FXNGdUM0puTVJNd0VRWURWUVFMRXdwUGNHVnVRbUZ2SUVOQk1STXdFUVlEVlFRRApFd3B2Y0dWdVltRnZMV05oTUI0WERUSTFNVEV4TVRBek1EQXdNRm9YRFRNMU1URXdPVEF6TURBd01Gb3dPekVQCk1BMEdBMVVFQ2hNR1FXNGdUM0puTVJNd0VRWURWUVFMRXdwUGNHVnVRbUZ2SUVOQk1STXdFUVlEVlFRREV3cHYKY0dWdVltRnZMV05oTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUF1dk9vRVRnLwpWRE9QT3ZjMjJ1RnliT0lEakRSdHpVUWQ0T3RFZ0tCODdOQXNuZFgzNUVldEJhOHlzNlR1YUMwNXBJbU1PdEVHCjloZW83VlEwQ1pNUEgvTnNza2Q0L0Fya3Iwb0VXdElHTzdiNkxZSFc4K2U0UTBuQ2tkV3RlVERrTHFiRXlHdmQKemhVa3NOMVlJcmhia0gvcFZzYmhMMWNHaGFMcHBwVFVVUG1CaW41RXRXblQ2Q1hqaDJxczV1UExRcWRmbkh5eQo4S0E4UHJJbTM2SG4wd1NybEFBWldOd3hmOWNsRWcyTEo1NlBDL25hSkVXbExReGNLWXRCWEpDdWNZSWVodXNBCjBhbFB6d1lpeUMxN0owdTY2MkYzQWg2VlBWZ1ZweW9KVTRXaDZveExWcElBd3RvaVBtbE5lVW9FTnZTaEljcGEKWDJyRFA5aHZYMCt2NnhPL3RJSDNRUDcrSGFaVS9OUHFQOHUvbk9ZUy9obWtiYmhpNEo1WGlxRzR3YVpGQmpNKworZHE1b0Z4aWNwTkp6ODJ2M3grQkpmYTNEYzZUajNhK3lpYmkxYTd5N0JrdVJ6WXpuaFJ0ZkxrNE0rV1hWSmpuCkpLaG1ydys2Y2UrQXRuQVo1R3JPZU1IT2FJeTEwZFkyK09YV1RsUUtsb0F4OEhCL0QycDg5bWV5UGUveXJSak4KTTF2QWRZVDE2aVhCNkcvYlJkZDU5eW5oZXV1dzI4OXhySm8vUXowWlROUmMxMVc3SWdubnNreksyTTREMVY0Vwo1RTNUNVM5YTdvckZEalFlMHc2cjQ3eWVzMjk4ekJMNE9YbVUzYmN0M2tCVkdES2l0a3pzQktDdU85QkhzZjkvCnNXRlN0OHozUThNV002QytpRUQ2cUhBRDhxMndOZDhUSXFFQ0F3RUFBYU5DTUVBd0RnWURWUjBQQVFIL0JBUUQKQWdLa01BOEdBMVVkRXdFQi93UUZNQU1CQWY4d0hRWURWUjBPQkJZRUZQWWtNYVdEQkhidGJWc3QwTy9oVVkxTQo4M0VaTUEwR0NTcUdTSWIzRFFFQkRRVUFBNElDQVFCN2VORGxrMXdaSWVDN2lhWlNtQTlSK0l0dWZURWh4U2ZyCmF0ZG9aUUR6azM3RTNzZmFDMTRBRzUwRkM5aEs3ZUQxVU5pZlYzcytCeUJoSkpWZWIzUmhTYjVkeGJkMjhTOG8KeXd0U2dzMis1ZFIzSVhjQ2U0bktxWCtjRi9UZU1DNEU0Nm5ib3cwZkFucXFvZ0VvNzc2dmMvNVdwM0lHNGlHbwpMd2E0NnV2YmV1RFR0WEEvYXlnUThxL0JuaWZOc3ZURldwbHFHd0tNckM5L3RubFFXcXZrOG4xN2o1eVp6czR4CmlCbW1oemRxOWRsSzlYQ0orVm45bWtxUWRwdUE5dGEzdng4c0NlNXNjN0o0Q0NnMmJpdVBoZWRkaUI3bTUrYVoKcVJLNS8vNEt0M2ZXNWtIMkJpUU1rOGplc0VLaCtDV21kZ1FKMWRUUXZLeWFHc0FJV0dyYWE1UTdaUGN2R0pkago2SlFzdUMyeW05b0p5RHpIVjBMYWErR0ZZL2pxc0VTSjFjRFJ1UHk4cWdJWTFEeEtHYVNUK1lJNnZpbGhlbVdyCjNkYWYydC9tclU3UkpGRXJZcnRORTdYVnhBL3VJeWJYTXdPTHVOMEZ4WFZlRElzZWlzUUZSM1F2ai9HTHdPMFIKZEZkRGd6ZW41dWZUMHhsTE1CUE5KOWt3RnpkamhSQkFZUXRUclA4SlAzb0wybmVyZVZ2Qmp1c2pISmlHY3RpRgo3QXVNT2I5MHNtN3JSUysvdWpqTjVtdE55Z2NwZVB1QkJzVnRCSlhlUXVOd0JpdVhSak9Oa1ljWSsvTTBES0x1CkFqQ0N1NUhJZVA0MW5GSU54TlNhMGl3MUZSclZHSmRSMHc5RU91ZWRiNmdZUEZBa0g2R2dJQkxwK0E2UGEybHYKditvZ0NubGZnQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
    
    # AppRole authentication
    auth:
      appRole:
        path: approle
        roleId: 999315e2-318e-5380-3a7f-a3ed3c7ed812  # Static role-id
        secretRef:
          name: metadata-bao-approle
          key: secret-id  # Reads rotated secret-id from Secret
```

**How cert-manager Uses AppRole:**

1. Reads `roleId` from Issuer spec (static)
2. Reads `secret-id` from Kubernetes Secret `metadata-bao-approle`
3. Authenticates to OpenBao using AppRole
4. Requests certificate signing from `nats_int/sign/metadata-tls-issuer`
5. Stores signed certificate in Kubernetes Secret

**Automatic Secret-ID Rotation:**

- cert-manager re-reads Secret on every certificate request
- VaultAppRoleSecretRotationVert updates Secret every 5 minutes
- cert-manager automatically picks up new secret-id
- No manual intervention required

### 5.2 Certificate Configuration

From `metadata-certificate.yaml`:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: metadata-nats-credential
  namespace: metadata
spec:
  isCA: false
  
  # Certificate lifetime
  duration: "6h"
  renewBefore: "3h"  # Renew halfway through lifetime
  
  # Certificate subject
  subject:
    organizations:
    - metadata
  
  # Private key configuration
  privateKey:
    algorithm: RSA
    size: 4096
    rotationPolicy: Always  # Generate new key on renewal
  
  # Certificate SANs
  commonName: metadata
  dnsNames:
  - localhost
  - metadata
  - metadata-service
  - metadata-service.metadata.svc.cluster.local
  ipAddresses:
  - 127.0.0.1
  - 10.1.1.12
  
  # Output secret
  secretName: metadata-nats-credential
  
  # Reference to Issuer
  issuerRef:
    name: metadata-tls-issuer
```

**Certificate Lifecycle:**

```
Timeline: Certificate Issuance and Renewal
-------------------------------------------

T=00:00:00 - Certificate resource created
             - cert-manager controller detects new Certificate
             - Generates RSA-4096 private key
             - Creates CSR (Certificate Signing Request)

T=00:00:05 - cert-manager authenticates to OpenBao
             - Reads role-id from Issuer spec
             - Reads secret-id from metadata-bao-approle Secret
             - POST /v1/auth/approle/login
             - Receives Vault token (TTL: 1 day)

T=00:00:10 - cert-manager requests certificate signing
             - POST /v1/nats_int/sign/metadata-tls-issuer
             - Includes CSR in request body
             - OpenBao signs CSR with Intermediate CA
             - Returns signed certificate

T=00:00:15 - cert-manager stores certificate
             - Updates metadata-nats-credential Secret
             - Stores: tls.crt, tls.key, ca.crt
             - Certificate valid for 6 hours

T=03:00:00 - Renewal triggered (renewBefore: 3h)
             - Generates new RSA-4096 key (rotationPolicy: Always)
             - Creates new CSR
             - Re-authenticates to OpenBao (may use new secret-id)
             - Requests new certificate signing
             - Updates Secret with new certificate + key

T=06:00:00 - Old certificate expires
             - Services already using new certificate (updated 3 hours ago)
             - Zero downtime
```

---

## 6. Application-Level OpenBao Access

### 6.1 MetadataServiceVert Initialization

From `MetadataServiceVert.java`:

```java
Project: svc-metadata
Package: verticle
Class:   MetadataServiceVert.java

/**
 * Main verticle for the Metadata Service.
 * 
 * Initializes VaultAccessHandler and deploys child verticles including
 * VaultAppRoleSecretRotationVert.
 */
public class MetadataServiceVert extends AbstractVerticle {
  
  private static final Logger LOGGER = LoggerFactory.getLogger(MetadataServiceVert.class);
  
  private static final String AppRoleSecretName = "metadata-bao-approle";
  private static final String AppRoleName = "metadata";
  private static final String VaultAgentAddr = "http://127.0.0.1:8100";
  private static final String VaultAgentHost = "127.0.0.1";
  private static final String VaultAgentPort = "8100";
  private static final String VaultTokenPath = "/home/bao/token";
  private static final String SecretIDRotationMs = "300000";  // 5 minutes
  
  private MetadataService svc;
  private KubernetesClient kubeClient;
  private NatsTLSClient natsTlsClient;
  private WorkerExecutor workerExecutor;
  private MetadataVaultHandler vaultHandler;
  private VaultAccessHandler accessHandler;
  private KeySecretManager keyCache;
  private DilithiumService signer;
  private MetadataConfig config;
  private String nameSpace;
  
  public MetadataServiceVert(Vertx vertx, MetadataService svc, KubernetesClient kubeClient,
                            MetadataConfig config, String nameSpace, NatsTLSClient natsTlsClient)
    throws Exception {
    
    this.svc = svc;
    this.kubeClient = kubeClient;
    this.config = config;
    this.nameSpace = nameSpace;
    this.natsTlsClient = natsTlsClient;
    
    String serviceId = config.getServiceId();
    
    // Get Vault Agent configuration from config (with defaults)
    String vaultAgentAddr = (config.getVault().getVaultAgentAddr() == null) 
      ? VaultAgentAddr 
      : config.getVault().getVaultAgentAddr();
    
    String vaultAgentHost = (config.getVault().getVaultAgentHost() == null) 
      ? VaultAgentHost 
      : config.getVault().getVaultAgentHost();
    
    String vaultAgentPort = (config.getVault().getVaultAgentPort() == null) 
      ? VaultAgentPort 
      : config.getVault().getVaultAgentPort();
    
    String vaultTokenPath = (config.getVault().getAppRoleTokenPath() == null) 
      ? VaultTokenPath 
      : config.getVault().getAppRoleTokenPath();
    
    int port = Integer.parseInt(vaultAgentPort);
    
    // Initialize VaultAccessHandler (connects to Agent on localhost:8100)
    this.accessHandler = new VaultAccessHandler(
      vertx, 
      serviceId, 
      vaultAgentAddr, 
      vaultAgentHost, 
      port, 
      vaultTokenPath
    );
    
    // Initialize MetadataVaultHandler (wraps VaultAccessHandler)
    this.vaultHandler = new MetadataVaultHandler(vertx, accessHandler);
    
    // Initialize KeySecretManager (uses VaultAccessHandler for ServiceBundle retrieval)
    this.keyCache = new KeySecretManager(vertx, accessHandler);
  }
  
  @Override
  public void start(Promise<Void> startPromise) throws Exception {
    workerExecutor = vertx.createSharedWorkerExecutor("msg-handler");
    
    deployVerticles()
      .compose(v -> Future.succeededFuture())
      .onSuccess(v -> {
        LOGGER.info("MetadataServiceVert started successfully");
        startPromise.complete();
      })
      .onFailure(throwable -> {
        String msg = "Fatal error during verticle deployment: " + throwable.getMessage();
        LOGGER.error(msg, throwable);
        svc.cleanupResources();
        startPromise.fail(msg);
      });
  }
  
  /**
   * Deploys core verticles including VaultAppRoleSecretRotationVert.
   */
  private Future<Void> deployVerticles() throws Exception {
    DeploymentOptions workerOptions = new DeploymentOptions()
      .setConfig(new JsonObject().put("worker", true));
    DeploymentOptions eventLoopOptions = new DeploymentOptions();
    
    List<ChildVerticle> childDeployments = svc.getDeployedVerticles();
    Promise<Void> deploymentPromise = Promise.promise();
    
    workerExecutor.executeBlocking(() -> {
      try {
        // Deploy ServicesACLWatcherVert
        ServicesACLWatcherVert aclWatcherVert = new ServicesACLWatcherVert(
          keyCache, kubeClient, vaultHandler, config
        );
        Future<String> aclWatcherFuture = deployVerticle(
          aclWatcherVert, workerOptions, "ServicesACLsWatcherVert"
        );
        
        // Deploy MetadataKeyExchangeVert
        MetadataKeyExchangeVert keyExchangeVert = new MetadataKeyExchangeVert(
          natsTlsClient, keyCache
        );
        Future<String> keyExchangeFuture = deployVerticle(
          keyExchangeVert, workerOptions, "KeyExchangeVert"
        );
        
        // Deploy VaultAppRoleSecretRotationVert
        String appRoleSecretName = (config.getVault().getAppRoleSecretName() == null) 
          ? AppRoleSecretName 
          : config.getVault().getAppRoleSecretName();
        
        String appRoleName = (config.getVault().getAppRoleName() == null) 
          ? AppRoleName 
          : config.getVault().getAppRoleName();
        
        String secretIDRotationMs = (config.getVault().getSecretIDRotationMs() == null) 
          ? SecretIDRotationMs 
          : config.getVault().getSecretIDRotationMs();
        
        long rotationMs = Long.parseLong(secretIDRotationMs);
        
        VaultAppRoleSecretRotationVert appRoleRotator = new VaultAppRoleSecretRotationVert(
          kubeClient,
          nameSpace,
          appRoleSecretName,
          appRoleName,
          rotationMs,
          accessHandler
        );
        
        Future<String> secretRotationFuture = deployVerticle(
          appRoleRotator, eventLoopOptions, "VaultAppRoleSecretRotationVert"
        );
        
        // Initialize DilithiumService
        this.signer = new DilithiumService(workerExecutor);
        
        // Deploy CaRotatorVert
        CaRotatorVert caVert = new CaRotatorVert(
          vertx, kubeClient, natsTlsClient, vaultHandler, config, signer, keyCache
        );
        Future<String> caVertFuture = deployVerticle(
          caVert, eventLoopOptions, "CaRotatorVert"
        );
        
        // Wait for all deployments
        return Future.all(
          keyExchangeFuture,
          secretRotationFuture,
          aclWatcherFuture,
          caVertFuture
        );
        
      } catch (Exception e) {
        String msg = "Fatal error during verticles deployment";
        LOGGER.error(msg, e);
        svc.cleanupResources();
        throw new RuntimeException(msg, e);
      }
    }).onComplete(ar -> {
      if (ar.succeeded()) {
        CompositeFuture compositeFuture = (CompositeFuture) ar.result();
        String[] verticleNames = {
          "KeyExchangeVert",
          "VaultAppRoleSecretRotationVert",
          "ServicesACLsWatcherVert",
          "CaRotatorVert"
        };
        
        for (int i = 0; i < compositeFuture.size(); i++) {
          String deploymentId = compositeFuture.resultAt(i);
          childDeployments.add(new ChildVerticle(verticleNames[i], deploymentId));
          LOGGER.info("{} deployed successfully: {}", verticleNames[i], deploymentId);
        }
        
        LOGGER.info("All verticles deployed successfully");
        deploymentPromise.complete();
      } else {
        LOGGER.error("Worker execution failed: {}", ar.cause().getMessage());
        deploymentPromise.fail(ar.cause());
      }
    });
    
    return deploymentPromise.future();
  }
  
  private Future<String> deployVerticle(AbstractVerticle verticle, 
                                       DeploymentOptions options, 
                                       String name) {
    return vertx.deployVerticle(verticle, options)
      .onFailure(throwable -> 
        LOGGER.error("Failed to deploy {}: {}", name, throwable.getMessage())
      );
  }
}
```

### 6.2 VaultAccessHandler - Generic Vault Operations

Continued from Section 4.2:

```java
/**
 * Generic Vault API request via the Agent with JSON object payload.
 * 
 * Supports GET, POST, LIST, DELETE methods.
 * Automatically includes token in X-Vault-Token header.
 */
public Future<JsonObject> vaultRequest(String method, String path, String payloadJson) {
  Promise<JsonObject> promise = Promise.promise();
  
  getVaultToken().onSuccess(token -> {
    String url = vaultAgentAddr + path;
    LOGGER.debug("vaultRequest for path = {}", url);
    
    if ("POST".equalsIgnoreCase(method)) {
      JsonObject payload = payloadJson != null 
        ? new JsonObject(payloadJson) 
        : new JsonObject();
      
      webClient.postAbs(url)
        .putHeader("X-Vault-Token", token)
        .putHeader("Content-Type", "application/json")
        .as(BodyCodec.string())
        .sendJsonObject(payload)
        .onSuccess(response -> handleVaultResponse(response, promise))
        .onFailure(err -> {
          LOGGER.error("Vault POST HTTP request failed for url = {}: {}", 
                      url, err.getMessage());
          promise.fail(err);
        });
        
    } else if ("LIST".equalsIgnoreCase(method)) {
      webClient.getAbs(url)
        .addQueryParam("list", "true")
        .putHeader("X-Vault-Token", token)
        .as(BodyCodec.string())
        .send()
        .onSuccess(response -> handleVaultResponse(response, promise))
        .onFailure(err -> {
          LOGGER.error("Vault LIST HTTP request failed for url = {}: {}", 
                      url, err.getMessage());
          promise.fail(err);
        });
        
    } else if ("DELETE".equalsIgnoreCase(method)) {
      webClient.deleteAbs(url)
        .putHeader("X-Vault-Token", token)
        .as(BodyCodec.string())
        .send()
        .onSuccess(response -> handleVaultResponse(response, promise))
        .onFailure(err -> {
          LOGGER.error("Vault DELETE HTTP request failed for url = {}: {}", 
                      url, err.getMessage());
          promise.fail(err);
        });
        
    } else {  // GET and other methods
      webClient.getAbs(url)
        .putHeader("X-Vault-Token", token)
        .as(BodyCodec.string())
        .send()
        .onSuccess(response -> handleVaultResponse(response, promise))
        .onFailure(err -> {
          LOGGER.error("Vault GET HTTP request failed for url = {}: {}", 
                      url, err.getMessage());
          promise.fail(err);
        });
    }
  }).onFailure(promise::fail);
  
  return promise.future();
}

/**
 * Handle Vault JSON response consistently.
 */
private void handleVaultResponse(HttpResponse<String> response, Promise<JsonObject> promise) {
  if (response.statusCode() < 200 || response.statusCode() >= 300) {
    String errorMsg = "Vault request failed (status " + response.statusCode() + "): " + 
                     response.body();
    LOGGER.error(errorMsg);
    promise.fail(errorMsg);
  } else {
    try {
      String responseBody = response.body();
      if (responseBody == null || responseBody.trim().isEmpty()) {
        promise.complete(new JsonObject());
      } else {
        promise.complete(new JsonObject(responseBody));
      }
    } catch (Exception e) {
      LOGGER.error("Failed to parse Vault response: {}", e.getMessage());
      promise.fail(e);
    }
  }
}
```

### 6.3 ServiceBundle Retrieval from OpenBao

```java
/**
 * Retrieve a ServiceBundle for a given serviceId and epoch.
 * Vault path: secret/data/service-bundles/{serviceId}/{epoch}
 * 
 * This is called by KeySecretManager.loadServiceBundleForEpoch() when keys are missing.
 */
public Future<ServiceBundle> getServiceBundle(String serviceId, long epoch) {
  String path = String.format("%s/%s/%d", SERVICE_BUNDLE_VAULT_PATH_PREFIX, serviceId, epoch);
  String apiUrl = "/v1/" + SERVICE_BUNDLE_VAULT_MOUNT + "/data/" + path;
  
  return vaultRequest("GET", apiUrl, null)
    .compose(response -> {
      try {
        JsonObject dataOuter = response.getJsonObject("data");
        if (dataOuter == null) {
          return Future.failedFuture("No data field in response for " + serviceId + 
                                    " at epoch " + epoch);
        }
        
        JsonObject dataInner = dataOuter.getJsonObject("data");
        if (dataInner == null) {
          return Future.failedFuture("No inner data field in response for " + serviceId + 
                                    " at epoch " + epoch);
        }
        
        String base64Bundle = dataInner.getString("bundle", null);
        if (base64Bundle == null || base64Bundle.trim().isEmpty()) {
          return Future.failedFuture("No bundle found for " + serviceId + " at epoch " + epoch);
        }
        
        // Deserialize in worker thread (Avro deserialization is CPU-intensive)
        return vaultWorker.executeBlocking(() -> {
          byte[] avroBytes = Base64.getDecoder().decode(base64Bundle);
          return ServiceBundle.deSerialize(avroBytes);
        });
        
      } catch (Exception e) {
        return Future.failedFuture(e);
      }
    });
}

/**
 * List all epoch keys for a serviceId.
 * Vault path: secret/metadata/service-bundles/{serviceId}
 */
public Future<List<String>> listServiceBundleEpochs(String serviceId) {
  String path = String.format("%s/%s", SERVICE_BUNDLE_VAULT_PATH_PREFIX, serviceId);
  String apiUrl = "/v1/" + SERVICE_BUNDLE_VAULT_MOUNT + "/metadata/" + path;
  
  return vaultRequest("LIST", apiUrl, null)
    .map(response -> {
      JsonObject data = response.getJsonObject("data");
      if (data == null) {
        return new ArrayList<String>();
      }
      
      JsonArray keysArray = data.getJsonArray("keys");
      if (keysArray == null) {
        return new ArrayList<String>();
      }
      
      List<String> epochs = new ArrayList<>();
      for (int i = 0; i < keysArray.size(); i++) {
        String key = keysArray.getString(i);
        if (key.endsWith("/")) {
          key = key.substring(0, key.length() - 1);
        }
        epochs.add(key);
      }
      return epochs;
    });
}

/**
 * Retrieve all ServiceBundles for a given serviceId (all epochs).
 */
public Future<List<ServiceBundle>> getAllServiceBundles(String serviceId) {
  return listServiceBundleEpochs(serviceId)
    .compose(epochKeys -> {
      List<Future<ServiceBundle>> futures = new ArrayList<>();
      for (String epoch : epochKeys) {
        try {
          long epochLong = Long.parseLong(epoch);
          futures.add(getServiceBundle(serviceId, epochLong)
            .recover(err -> Future.succeededFuture(null)));
        } catch (NumberFormatException nfe) {
          LOGGER.warn("Ignoring invalid epoch key: {}", epoch);
        }
      }
      
      return Future.all(futures).map(cf -> {
        List<ServiceBundle> bundles = new ArrayList<>();
        for (Object b : cf.list()) {
          if (b instanceof ServiceBundle && b != null) {
            bundles.add((ServiceBundle) b);
          }
        }
        return bundles;
      });
    });
}
```

**ServiceBundle Storage Structure in OpenBao:**

```
secret/data/service-bundles/
├── metadata/
│   ├── 1957385   (epoch number)
│   ├── 1957386
│   ├── 1957387
│   └── ...
├── gatekeeper/
│   ├── 1957385
│   ├── 1957386
│   └── ...
├── authcontroller/
│   ├── 1957385
│   ├── 1957386
│   └── ...
└── watcher/
    ├── 1957385
    └── ...
```

**Example ServiceBundle JSON in OpenBao:**

```json
{
  "data": {
    "data": {
      "bundle": "base64-encoded-avro-serialized-ServiceBundle",
      "serviceId": "metadata",
      "epochNumber": 1957385,
      "created_at": "2025-01-17T10:00:00Z",
      "expires_at": "2025-01-17T11:00:00Z"
    },
    "metadata": {
      "created_time": "2025-01-17T10:00:00.123456Z",
      "deletion_time": "",
      "destroyed": false,
      "version": 1
    }
  }
}
```

### 6.4 CaBundle Retrieval from OpenBao

```java
/**
 * Retrieve a CaBundle for a given serverId and CA epoch.
 * Vault path: secret/data/ca-bundles/{serverId}/{caEpoch}
 */
public Future<CaBundle> getCaBundle(String serverId, long caEpoch) {
  String path = String.format("%s/%s/%d", CA_BUNDLE_VAULT_PATH_PREFIX, serverId, caEpoch);
  String apiUrl = "/v1/" + SERVICE_BUNDLE_VAULT_MOUNT + "/data/" + path;
  
  return vaultRequest("GET", apiUrl, null)
    .compose(response -> {
      try {
        JsonObject dataOuter = response.getJsonObject("data");
        if (dataOuter == null) {
          return Future.failedFuture("No data field in response for " + serverId + 
                                    " at CA epoch " + caEpoch);
        }
        
        JsonObject dataInner = dataOuter.getJsonObject("data");
        if (dataInner == null) {
          return Future.failedFuture("No inner data field in response for " + serverId + 
                                    " at CA epoch " + caEpoch);
        }
        
        String base64Bundle = dataInner.getString("bundle", null);
        if (base64Bundle == null || base64Bundle.trim().isEmpty()) {
          return Future.failedFuture("No bundle found for " + serverId + 
                                    " at CA epoch " + caEpoch);
        }
        
        return vaultWorker.executeBlocking(() -> {
          byte[] avroBytes = Base64.getDecoder().decode(base64Bundle);
          return CaBundle.deSerialize(avroBytes);
        });
        
      } catch (Exception e) {
        LOGGER.error("Failed to deserialize CaBundle for {} at epoch {}: {}", 
                    serverId, caEpoch, e.getMessage(), e);
        return Future.failedFuture(e);
      }
    });
}

/**
 * List all CA epoch keys for a serverId.
 * Vault path: secret/metadata/ca-bundles/{serverId}
 */
public Future<List<Long>> listCaBundleEpochs(String serverId) {
  String path = String.format("%s/%s", CA_BUNDLE_VAULT_PATH_PREFIX, serverId);
  String apiUrl = "/v1/" + SERVICE_BUNDLE_VAULT_MOUNT + "/metadata/" + path;
  
  return vaultRequest("LIST", apiUrl, null)
    .map(response -> {
      JsonObject data = response.getJsonObject("data");
      if (data == null) {
        return new ArrayList<Long>();
      }
      
      JsonArray keysArray = data.getJsonArray("keys");
      if (keysArray == null) {
        return new ArrayList<Long>();
      }
      
      List<Long> epochs = new ArrayList<>();
      for (int i = 0; i < keysArray.size(); i++) {
        String key = keysArray.getString(i);
        if (key.endsWith("/")) {
          key = key.substring(0, key.length() - 1);
        }
        try {
          epochs.add(Long.parseLong(key));
        } catch (NumberFormatException nfe) {
          LOGGER.warn("Ignoring invalid CA epoch key: {}", key);
        }
      }
      return epochs;
    });
}

/**
 * Get the most recent CaBundle for a given serverId.
 * This is useful for services that just need the current CA bundle.
 */
public Future<CaBundle> getCurrentCaBundle(String serverId) {
  return listCaBundleEpochs(serverId)
    .compose(epochs -> {
      if (epochs == null || epochs.isEmpty()) {
        return Future.failedFuture("No CA bundles found for server " + serverId);
      }
      
      // Get the highest epoch number (most recent)
      Long maxEpoch = Collections.max(epochs);
      LOGGER.info("Retrieving current CA bundle for server {} at epoch {}", 
                  serverId, maxEpoch);
      
      return getCaBundle(serverId, maxEpoch);
    });
}

/**
 * Retrieve all CaBundles for a given serverId (all CA epochs).
 */
public Future<List<CaBundle>> getAllCaBundles(String serverId) {
  return listCaBundleEpochs(serverId)
    .compose(epochKeys -> {
      if (epochKeys == null || epochKeys.isEmpty()) {
        LOGGER.info("No CA bundles found for server {}", serverId);
        return Future.succeededFuture(new ArrayList<CaBundle>());
      }
      
      List<Future<CaBundle>> futures = new ArrayList<>();
      for (Long epoch : epochKeys) {
        futures.add(getCaBundle(serverId, epoch).recover(err -> {
          LOGGER.warn("Failed to retrieve CA bundle for {} at epoch {}: {}", 
                     serverId, epoch, err.getMessage());
          return Future.succeededFuture(null);
        }));
      }
      
      return Future.all(futures).map(cf -> {
        List<CaBundle> bundles = new ArrayList<>();
        for (Object b : cf.list()) {
          if (b instanceof CaBundle && b != null) {
            bundles.add((CaBundle) b);
          }
        }
        LOGGER.info("Retrieved {} CA bundles for server {}", bundles.size(), serverId);
        return bundles;
      });
    });
}

@Override
public void close() {
  if (vaultWorker != null) {
    vaultWorker.close();
  }
  if (webClient != null) {
    webClient.close();
  }
}
```

**CaBundle Storage Structure in OpenBao:**

```
secret/data/ca-bundles/
├── NATS/
│   ├── 36945   (CA epoch number)
│   ├── 36946
│   ├── 36947
│   └── ...
└── metadata/
    ├── 36945
    ├── 36946
    └── ...
```

---

## 7. MetadataVaultHandler - Domain-Specific Operations

### 7.1 MetadataVaultHandler Architecture

From `MetadataVaultHandler.java`:

```java
Project: svc-metadata
Package: handler
Class:   MetadataVaultHandler.java

/**
 * MetadataVaultHandler - High-level Vault operations for Metadata service.
 * 
 * Wraps VaultAccessHandler with domain-specific methods for:
 * - ServiceBundle storage and retrieval
 * - CaBundle storage and retrieval
 * - PKI certificate operations (CA rotation)
 * - Signing key management
 */
public class MetadataVaultHandler {
  
  private static final Logger LOGGER = LoggerFactory.getLogger(MetadataVaultHandler.class);
  
  private final Vertx vertx;
  private final VaultAccessHandler vaultAccessHandler;
  
  public MetadataVaultHandler(Vertx vertx, VaultAccessHandler vaultAccessHandler) {
    this.vertx = vertx;
    this.vaultAccessHandler = vaultAccessHandler;
  }
  
  /**
   * Store a ServiceBundle in OpenBao.
   * Vault path: secret/data/service-bundles/{serviceId}/{epoch}
   */
  public Future<Void> storeServiceBundle(ServiceBundle bundle) {
    String serviceId = bundle.getServiceId();
    long epoch = bundle.getKeyEpoch();
    
    return vertx.executeBlocking(() -> {
      try {
        // Serialize ServiceBundle to Avro
        byte[] avroBytes = ServiceBundle.serialize(bundle);
        String base64Bundle = Base64.getEncoder().encodeToString(avroBytes);
        
        // Build Vault payload
        JsonObject data = new JsonObject()
          .put("bundle", base64Bundle)
          .put("serviceId", serviceId)
          .put("epochNumber", epoch)
          .put("created_at", Instant.now().toString())
          .put("expires_at", bundle.getExpiryTime().toString());
        
        JsonObject payload = new JsonObject().put("data", data);
        
        String path = String.format("secret/data/service-bundles/%s/%d", serviceId, epoch);
        String apiUrl = "/v1/" + path;
        
        return vaultAccessHandler.vaultRequest("POST", apiUrl, payload.encode())
          .mapEmpty();
        
      } catch (Exception e) {
        LOGGER.error("Failed to store ServiceBundle for {} at epoch {}: {}", 
                    serviceId, epoch, e.getMessage(), e);
        return Future.failedFuture(e);
      }
    });
  }
  
  /**
   * Store a CaBundle in OpenBao.
   * Vault path: secret/data/ca-bundles/{serverId}/{caEpoch}
   */
  public Future<Void> storeCaBundle(CaBundle bundle) {
    String serverId = bundle.getServerId();
    long caEpoch = bundle.getCaEpoch();
    
    return vertx.executeBlocking(() -> {
      try {
        // Serialize CaBundle to Avro
        byte[] avroBytes = CaBundle.serialize(bundle);
        String base64Bundle = Base64.getEncoder().encodeToString(avroBytes);
        
        // Build Vault payload
        JsonObject data = new JsonObject()
          .put("bundle", base64Bundle)
          .put("serverId", serverId)
          .put("caEpoch", caEpoch)
          .put("created_at", Instant.now().toString())
          .put("validUntil", bundle.getValidUntil().toString());
        
        JsonObject payload = new JsonObject().put("data", data);
        
        String path = String.format("secret/data/ca-bundles/%s/%d", serverId, caEpoch);
        String apiUrl = "/v1/" + path;
        
        return vaultAccessHandler.vaultRequest("POST", apiUrl, payload.encode())
          .mapEmpty();
        
      } catch (Exception e) {
        LOGGER.error("Failed to store CaBundle for {} at CA epoch {}: {}", 
                    serverId, caEpoch, e.getMessage(), e);
        return Future.failedFuture(e);
      }
    });
  }
  
  /**
   * Get ServiceBundle from OpenBao (delegates to VaultAccessHandler).
   */
  public Future<ServiceBundle> getServiceBundle(String serviceId, long epoch) {
    return vaultAccessHandler.getServiceBundle(serviceId, epoch);
  }
  
  /**
   * Get CaBundle from OpenBao (delegates to VaultAccessHandler).
   */
  public Future<CaBundle> getCaBundle(String serverId, long caEpoch) {
    return vaultAccessHandler.getCaBundle(serverId, caEpoch);
  }
  
  /**
   * Get current (most recent) CaBundle for a server.
   */
  public Future<CaBundle> getCurrentCaBundle(String serverId) {
    return vaultAccessHandler.getCurrentCaBundle(serverId);
  }
}
```

---

## 8. Practical Usage Examples

### 8.1 Key Exchange with ServiceBundle Delivery

From `MetadataKeyExchangeVert.java`:

```java
Project: svc-metadata
Package: verticle
Class:   MetadataKeyExchangeVert.java

/**
 * Process Kyber key exchange request and respond with ServiceBundle.
 * 
 * This demonstrates the complete flow:
 * 1. Perform Kyber key exchange
 * 2. Fetch ServiceBundle from event bus (ServicesACLWatcherVert)
 * 3. Encrypt ServiceBundle with Kyber shared secret
 * 4. Sign encrypted bundle (SignedMessage)
 * 5. Send response to requesting service
 */
protected Future<Void> processKeyExchRequestAsync(KyberExchangeMessage kyberMsg) {
  Promise<Void> promise = Promise.promise();
  
  try {
    LOGGER.info("Processing key exchange request from: {}", kyberMsg.getSourceSvcId());
    
    // Step 1: Perform Kyber key exchange
    PublicKey publicKey = KyberKEMCrypto.decodePublicKey(kyberMsg.getPublicKey());
    SecretKeyWithEncapsulation encapsulation = 
      KyberKEMCrypto.processKyberExchangeRequest(KyberKEMCrypto.encodePublicKey(publicKey));
    
    SharedSecretInfo keyInfo = SharedSecretInfo.buildSharedSecret(
      kyberMsg, publicKey, encapsulation.getEncoded()
    );
    
    String responseType = ServiceCoreIF.KyberKeyRequest.equals(kyberMsg.getEventType()) 
      ? ServiceCoreIF.KyberKeyResponse 
      : ServiceCoreIF.KyberRotateResponse;
    
    // Step 2: Create base response
    KyberExchangeMessage responseMsg = new KyberExchangeMessage(
      kyberMsg.getSecretKeyId(),
      "metadata",
      kyberMsg.getSourceSvcId(),
      responseType,
      kyberMsg.getPublicKey(),
      encapsulation.getEncapsulation(),
      kyberMsg.getCreateTime(),
      kyberMsg.getExpiryTime()
    );
    
    // Step 3: Generate and attach signed ServiceBundle
    generateSignedMessage(kyberMsg.getSourceSvcId(), keyInfo)
      .onComplete(ar -> {
        try {
          if (ar.succeeded()) {
            SignedMessage signedMsg = ar.result();
            
            LOGGER.info("Created SignedMessage containing ServiceBundle");
            LOGGER.info("Message Type = {}", signedMsg.getMessageType());
            LOGGER.info("Payload length = {}", signedMsg.getPayload().length);
            
            responseMsg.setAdditionalData(SignedMessage.serialize(signedMsg));
            LOGGER.info("Successfully processed key exchange for: {}", 
                       kyberMsg.getSourceSvcId());
            
            // Step 4: Send response with encrypted ServiceBundle
            sendKeyExchangeMessage(kyberMsg.getSourceSvcId(), responseMsg);
            keyCache.putEncyptionSharedSecret(keyInfo);
            
            promise.complete();
          } else {
            LOGGER.error("Failed to process ServiceBundle for {}: {}", 
                        kyberMsg.getSourceSvcId(), ar.cause().getMessage(), ar.cause());
            
            // Send response without ServiceBundle as fallback
            sendKeyExchangeMessage(kyberMsg.getSourceSvcId(), responseMsg);
            keyCache.putEncyptionSharedSecret(keyInfo);
            
            promise.complete();
          }
        } catch (Exception e) {
          String errMsg = "Error sending KyberMsg response: " + e.getMessage();
          LOGGER.error(errMsg, e);
          promise.fail(new RuntimeException(errMsg));
        }
      });
      
  } catch (Exception e) {
    LOGGER.error("Exception in processKeyExchRequestAsync: {}", e.getMessage(), e);
    promise.fail(e);
  }
  
  return promise.future();
}

/**
 * Get current ServiceBundle for target service from event bus.
 * 
 * This demonstrates how services request data from other verticles
 * without direct OpenBao access.
 */
public Future<ServiceBundle> getCurrentServiceBundle(String serviceId) {
  return vertx.eventBus().<Buffer>request(
    ServicesACLWatcherVert.SERVICE_BUNDLE_REQUEST_ADDR,
    serviceId
  )
  .compose(msg -> {
    try {
      ServiceBundle bundle = ServiceBundle.deSerialize(msg.body().getBytes());
      return Future.succeededFuture(bundle);
    } catch (Exception e) {
      return Future.failedFuture(e);
    }
  });
}

/**
 * Generate SignedMessage containing ServiceBundle encrypted with shared secret.
 */
private Future<SignedMessage> generateSignedMessage(String targetServiceId, 
                                                    SharedSecretInfo sharedSecret) {
  LOGGER.info("Generating ServiceBundle for service: {}", targetServiceId);
  
  return getCurrentServiceBundle(targetServiceId)
    .compose(bundle -> 
      workerExecutor.executeBlocking(() -> {
        byte[] serializedBundle = ServiceBundle.serialize(bundle);
        if (serializedBundle == null || serializedBundle.length == 0) {
          throw new RuntimeException("Failed to serialize ServiceBundle for: " + 
                                    targetServiceId);
        }
        return serializedBundle;
      })
    )
    .compose(serializedBundle -> {
      String subject = ServiceCoreIF.KeyExchangeStreamBase + targetServiceId;
      return signedMessageProcessor.createSignedMessage(
        targetServiceId,
        serializedBundle,
        "ServiceBundle",
        "ServiceBundle",
        subject,
        sharedSecret.getSharedSecret()  // Encrypt with Kyber shared secret
      );
    })
    .onFailure(err -> {
      LOGGER.error("Failed to process ServiceBundle for service: {}", targetServiceId, err);
    });
}
```

**Complete Flow Diagram:**

```
Requesting Service (e.g., Gatekeeper)
  │
  │ 1. Generate Kyber keypair
  │ 2. Send KyberExchangeMessage with public key
  │
  ▼
NATS JetStream (KEY_EXCHANGE stream)
  │
  ▼
Metadata Service - MetadataKeyExchangeVert
  │
  ├─ 3. Perform Kyber encapsulation
  │    └─> Generate shared secret
  │
  ├─ 4. Request ServiceBundle via event bus
  │    └─> ServicesACLWatcherVert responds with bundle
  │
  ├─ 5. Serialize ServiceBundle to Avro
  │
  ├─ 6. Create SignedMessage
  │    ├─> Encrypt with Kyber shared secret
  │    ├─> Sign with Metadata's Dilithium key
  │    └─> encryptKeyId = "shared-secret-<timestamp>"
  │
  ├─ 7. Serialize SignedMessage
  │
  └─ 8. Send KyberExchangeMessage response
       ├─> ciphertext (Kyber encapsulation)
       ├─> additionalData (SignedMessage)
       └─> NATS topic: "metadata.key-exchange.gatekeeper"
  │
  ▼
Requesting Service (Gatekeeper)
  │
  ├─ 9. Perform Kyber decapsulation with private key
  │    └─> Derive shared secret
  │
  ├─ 10. Extract SignedMessage from additionalData
  │
  ├─ 11. Decrypt SignedMessage
  │     ├─> Use shared secret (not topic key)
  │     ├─> Verify Dilithium signature
  │     └─> Deserialize ServiceBundle
  │
  └─ 12. Load ServiceBundle into KeyCache
       ├─> Topic encryption keys
       ├─> Signing keys
       ├─> Verification keys
       └─> Ready for secure messaging
```

### 8.2 CA Certificate Management

**Storing CA Bundle after Rotation:**

```java
Project: svc-metadata
Package: verticle
Class:   CaRotatorVert.java

/**
 * After generating and signing new CA certificate, store in OpenBao.
 */
private Future<Void> storeCaBundleInVault(CaBundle caBundle) {
  LOGGER.info("Storing CA bundle in OpenBao: serverId={}, caEpoch={}", 
              caBundle.getServerId(), caBundle.getCaEpoch());
  
  return vaultHandler.storeCaBundle(caBundle)
    .onSuccess(v -> {
      LOGGER.info("✅ Successfully stored CA bundle in OpenBao: serverId={}, caEpoch={}", 
                  caBundle.getServerId(), caBundle.getCaEpoch());
    })
    .onFailure(err -> {
      LOGGER.error("❌ Failed to store CA bundle in OpenBao: serverId={}, caEpoch={}: {}", 
                   caBundle.getServerId(), caBundle.getCaEpoch(), err.getMessage(), err);
    });
}
```

**Retrieving CA Bundle for Verification:**

```java
/**
 * Watcher service retrieves CA bundle to verify NATS server certificates.
 */
public Future<CaBundle> loadCurrentNatsCaBundle() {
  LOGGER.info("Loading current NATS CA bundle from OpenBao");
  
  return vaultAccessHandler.getCurrentCaBundle("NATS")
    .onSuccess(bundle -> {
      LOGGER.info("✅ Retrieved NATS CA bundle: caEpoch={}, validUntil={}", 
                  bundle.getCaEpoch(), bundle.getValidUntil());
      
      // Store CA certificate for NATS client TLS verification
      storeCaCertificate(bundle.getCaCertPem());
    })
    .onFailure(err -> {
      LOGGER.error("❌ Failed to retrieve NATS CA bundle: {}", err.getMessage(), err);
    });
}

private void storeCaCertificate(String caCertPem) {
  try {
    Path caPath = Paths.get("/etc/nats-ca-certs/ca.crt");
    Files.writeString(caPath, caCertPem);
    LOGGER.info("✅ Wrote NATS CA certificate to {}", caPath);
  } catch (Exception e) {
    LOGGER.error("❌ Failed to write CA certificate: {}", e.getMessage(), e);
  }
}
```

### 8.3 Service Bootstrap Flow

**Complete startup sequence for Metadata service:**

```
Metadata Pod Startup
--------------------

T=0s: Pod scheduled by Kubernetes
      - bao-agent container starts
      - metadata container starts (parallel)

T=1s: bao-agent container initialization
      ├─ Read role-id from /etc/bao/role-id (from Secret projection)
      ├─ Read secret-id from /etc/bao/secret-id (from Secret projection)
      ├─ Read OpenBao CA from /etc/bao/ca/ca.crt
      └─ Start agent with config from /etc/bao-agent/agent.hcl

T=2s: bao-agent AppRole authentication
      ├─ POST https://openbao.openbao.svc.cluster.local:8200/v1/auth/approle/login
      │   Body: {"role_id": "...", "secret_id": "..."}
      ├─ Receive token (TTL: 1 day)
      └─ Write token to /home/bao/token (shared PVC)

T=3s: bao-agent local proxy ready
      └─ Listening on 127.0.0.1:8100

T=4s: metadata container initialization
      ├─ Read config from /app/config/metadata-configmap
      ├─ Initialize VaultAccessHandler
      │   └─ vaultAgentHost: "127.0.0.1", vaultAgentPort: 8100
      └─ Initialize MetadataVaultHandler(vaultAccessHandler)

T=5s: MetadataServiceVert.start()
      ├─ Deploy ServicesACLWatcherVert
      │   ├─ Watch ConfigMaps for ServiceACL changes
      │   ├─ Generate ServiceBundles for all services
      │   └─ Store in OpenBao via vaultHandler.storeServiceBundle()
      │
      ├─ Deploy MetadataKeyExchangeVert
      │   └─ Bind to NATS KEY_EXCHANGE stream consumer
      │
      ├─ Deploy VaultAppRoleSecretRotationVert
      │   ├─ Read current role-id from K8s Secret
      │   ├─ Get Vault token from /home/bao/token
      │   ├─ Request new secret-id via vaultAccessHandler.requestNewSecretId()
      │   ├─ Update K8s Secret with new secret-id
      │   └─ Schedule rotation every 5 minutes
      │
      └─ Deploy CaRotatorVert
          └─ Manage CA certificate rotation

T=6s: First ServiceBundle generation
      ├─ ServicesACLWatcherVert processes all ServiceACLs
      ├─ Generate topic keys, signing keys, verification keys
      ├─ Build ServiceBundle for each service
      ├─ Serialize to Avro
      ├─ Base64 encode
      └─ Store in OpenBao: secret/data/service-bundles/{serviceId}/{epoch}

T=10s: First secret-id rotation
       ├─ VaultAppRoleSecretRotationVert.rotateSecretIdAsync()
       ├─ vaultAccessHandler.getVaultToken() reads /home/bao/token
       ├─ vaultAccessHandler.requestNewSecretId("metadata", token)
       ├─ OpenBao generates new secret-id (TTL: 12 hours)
       └─ Update metadata-bao-approle Secret

T=20s: bao-agent detects new secret-id
       ├─ secret_id_refresh_interval = 10s triggered
       ├─ Re-authenticate with new secret-id
       ├─ Receive new token
       └─ Write to /home/bao/token (overwrites old token)

T=300s (5 min): Next secret-id rotation cycle
T=600s (10 min): Next rotation cycle...
```

---

## 9. Security Considerations

### 9.1 Threat Model

**Protected Against:**

| Threat | Mitigation |
|--------|-----------|
| **Credential theft from Pod** | role-id and secret-id never exposed to metadata container |
| **Token compromise** | Tokens have 1-day TTL, automatically renewed |
| **Secret-id expiration** | Rotated every 5 minutes (TTL: 12 hours) |
| **Man-in-the-middle** | TLS with CA certificate verification |
| **Unauthorized Vault access** | Policy-based access control per service |
| **Secret exposure in logs** | Tokens read from file, never logged |
| **Container escape** | Pod security context prevents privilege escalation |
| **Network eavesdropping** | All Vault communication over TLS |

**Residual Risks:**

| Risk | Impact | Mitigation Strategy |
|------|--------|---------------------|
| **OpenBao compromise** | Critical (all secrets exposed) | Regular auditing, network segmentation, minimal permissions |
| **Kubernetes API compromise** | High (can modify Secrets) | RBAC restrictions, audit logging |
| **PVC compromise** | Medium (token file exposed) | Token TTL limits exposure window |
| **Agent sidecar vulnerability** | High (token generation compromised) | Keep OpenBao Agent updated, monitor CVEs |

### 9.2 Best Practices

**1. Minimize Token TTL:**

```hcl
# In AppRole configuration
token_ttl = 1d        # Minimize lifetime
token_max_ttl = 1d    # Prevent extension
```

**2. Rotate Secret-ID Frequently:**

```java
// VaultAppRoleSecretRotationVert
private static final String SecretIDRotationMs = "300000";  // 5 minutes

// Why 5 minutes when TTL is 12 hours?
// - Limits exposure window to 5 minutes
// - 144 rotations per 12-hour period
// - Secret-id never expires in practice
```

**3. Use Separate AppRoles Per Service:**

```bash
# metadata AppRole
bao write auth/approle/role/metadata \
  token_policies="metadata-policy,metadata-tls-issuer" \
  ...

# gatekeeper AppRole
bao write auth/approle/role/gatekeeper \
  token_policies="gatekeeper-policy,gatekeeper-tls-issuer" \
  ...

# Principle of least privilege: each service gets only required permissions
```

**4. Enable Audit Logging:**

```
# In OpenBao server configuration
bao audit enable file file_path=/vault/logs/audit.log

# Logs all access:
# - Who accessed what secret
# - When it was accessed
# - What operation was performed
# - Whether it succeeded or failed
```

**5. Monitor Secret-ID Rotation:**

```
// Add metrics in VaultAppRoleSecretRotationVert
private final AtomicLong rotationSuccessCount = new AtomicLong(0);
private final AtomicLong rotationFailureCount = new AtomicLong(0);

private void updateK8sSecretWithNewSecretId(Secret k8sSecret, String newSecretId) {
  try {
    // ... update logic ...
    rotationSuccessCount.incrementAndGet();
    LOGGER.info("✅ Updated secret_id for role {} (success count: {})", 
                vaultRoleName, rotationSuccessCount.get());
  } catch (Exception e) {
    rotationFailureCount.incrementAndGet();
    LOGGER.error("❌ Failed to update K8s Secret (failure count: {})", 
                 rotationFailureCount.get());
  }
}
```



**Alert on failures:**

```
# Prometheus alert
- alert: SecretIDRotationFailure
  expr: rate(secret_id_rotation_failures[5m]) > 0
  for: 10m
  labels:
    severity: critical
  annotations:
    summary: "Secret-ID rotation failing for {% raw %}{{ $labels.service }}{% endraw %}"
```

### 9.3 Network Security

**OpenBao Access Path:**

```
metadata container (localhost:8100)
  │
  │ 1. HTTP request to Agent proxy
  │
  ▼
bao-agent sidecar (127.0.0.1:8100)
  │
  │ 2. Add X-Vault-Token header
  │ 3. Forward via Kubernetes cluster network
  │
  ▼
Istio sidecar (if deployed)
  │
  │ 4. mTLS encryption
  │
  ▼
Istio Gateway (openbao.openbao.svc.cluster.local:8200)
  │
  │ 5. TLS termination
  │ 6. Route to OpenBao pod
  │
  ▼
OpenBao Server (openbao-0.openbao.svc.cluster.local:8200)
  │
  │ 7. Validate token
  │ 8. Check policy permissions
  │ 9. Return secret
  │
  ▼
Response flows back through same path
```

**Network Policies:**

```yaml
# Restrict metadata namespace to only access OpenBao
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: metadata-vault-access
  namespace: metadata
spec:
  podSelector:
    matchLabels:
      app: metadata
  policyTypes:
  - Egress
  egress:
  # Allow DNS
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53
  # Allow OpenBao
  - to:
    - namespaceSelector:
        matchLabels:
          name: openbao
    ports:
    - protocol: TCP
      port: 8200
  # Allow NATS
  - to:
    - namespaceSelector:
        matchLabels:
          name: nats
    ports:
    - protocol: TCP
      port: 4222
```

---

## 10. Troubleshooting and Monitoring

### 10.1 Common Issues

**Issue 1: "Vault token not found"**

```bash
# Symptom
VaultAccessHandler - Vault token read failed: java.nio.file.NoSuchFileException: /home/bao/token

# Diagnosis
kubectl exec -n metadata metadata-xxx -c bao-agent -- ls -la /home/bao/
# Check if token file exists

# Causes
1. Agent failed to authenticate
2. PVC not mounted correctly
3. Agent crashed before writing token

# Solution
# Check Agent logs
kubectl logs -n metadata metadata-xxx -c bao-agent

# Verify AppRole credentials
kubectl get secret -n metadata metadata-bao-approle -o yaml
# Decode and verify role-id and secret-id

# Restart pod if PVC issue
kubectl delete pod -n metadata metadata-xxx
```

**Issue 2: "Secret-id rotation failing"**

```bash
# Symptom
VaultAppRoleSecretRotationVert - Failed to rotate secret-id: 403 Forbidden

# Diagnosis
kubectl logs -n metadata metadata-xxx -c metadata | grep "secret-id"

# Causes
1. Token lacks permission for auth/approle/role/metadata/secret-id
2. Token expired
3. AppRole policy missing

# Solution
# Check token permissions
kubectl exec -n openbao openbao-0 -- bao token lookup -ca-cert=/openbao/userconfig/openbao-tls/openbao.ca $TOKEN

# Verify policy includes
path "auth/approle/role/metadata/secret-id" {
  capabilities = ["update", "create"]
}

# Re-apply policy if needed
./Step-05-OpenBao-ConfigureAuthAndIssuers.sh
```

**Issue 3: "cert-manager certificate not issued"**

```bash
# Symptom
kubectl get certificate -n metadata metadata-nats-credential
# Shows: Ready=False, Reason=Pending

# Diagnosis
kubectl describe certificate -n metadata metadata-nats-credential
# Check Events section

# Common causes
1. Issuer cannot authenticate to OpenBao
2. PKI role not configured
3. Secret-id expired (not rotated)

# Solution
# Check Issuer status
kubectl describe issuer -n metadata metadata-tls-issuer

# Verify AppRole secret
kubectl get secret -n metadata metadata-bao-approle -o jsonpath='{.data.secret-id}' | base64 -d
# Should be non-empty and recent

# Test OpenBao PKI endpoint
kubectl exec -n openbao openbao-0 -- \
  bao read -ca-cert=/openbao/userconfig/openbao-tls/openbao.ca \
  nats_int/roles/metadata-tls-issuer
```

**Issue 4: "ServiceBundle not found in OpenBao"**

```bash
# Symptom
VaultAccessHandler - No bundle found for metadata at epoch 1957385

# Diagnosis
kubectl exec -n openbao openbao-0 -- \
  bao kv list -ca-cert=/openbao/userconfig/openbao-tls/openbao.ca \
  secret/service-bundles/metadata

# Causes
1. ServicesACLWatcherVert not running
2. ServiceBundle generation failed
3. Vault write permission missing

# Solution
# Check ServicesACLWatcherVert logs
kubectl logs -n metadata metadata-xxx -c metadata | grep "ServicesACLWatcherVert"

# Manually verify ServiceBundle storage
kubectl logs -n metadata metadata-xxx -c metadata | grep "storeServiceBundle"

# Check Vault permissions
kubectl exec -n openbao openbao-0 -- \
  bao policy read -ca-cert=/openbao/userconfig/openbao-tls/openbao.ca metadata-policy
# Should include:
# path "secret/data/service-bundles/*" { capabilities = ["create", "update", "read"] }
```

### 10.2 Health Checks

**Agent Health Check:**

```yaml
# Add to metadata Deployment
livenessProbe:
  exec:
    command:
    - /bin/sh
    - -c
    - "test -f /home/bao/token && [ $(find /home/bao/token -mmin -60 | wc -l) -eq 1 ]"
  initialDelaySeconds: 30
  periodSeconds: 60
```

**Vault Connectivity Check:**

```java
/**
 * Periodic health check for Vault connectivity.
 */
private void setupVaultHealthCheck() {
  vertx.setPeriodic(60000, id -> {
    vaultAccessHandler.getVaultToken()
      .compose(token -> {
        // Token lookup verifies Vault connectivity
        String apiUrl = "/v1/auth/token/lookup-self";
        return vaultAccessHandler.vaultRequest("GET", apiUrl, null);
      })
      .onSuccess(response -> {
        LOGGER.debug("✅ Vault health check passed");
        healthCheckSuccessCount.incrementAndGet();
      })
      .onFailure(err -> {
        LOGGER.error("❌ Vault health check failed: {}", err.getMessage());
        healthCheckFailureCount.incrementAndGet();
      });
  });
}
```

### 10.3 Metrics

**Key Metrics to Monitor:**

```java
// VaultAppRoleSecretRotationVert
metrics.counter("vault.secret_id.rotation.success");
metrics.counter("vault.secret_id.rotation.failure");
metrics.gauge("vault.secret_id.age_seconds", () -> {
  // Time since last rotation
});

// VaultAccessHandler
metrics.timer("vault.request.duration");
metrics.counter("vault.request.success");
metrics.counter("vault.request.failure");
metrics.gauge("vault.token.age_seconds", () -> {
  // Time since token was written
});

// cert-manager (external)
# Provided by cert-manager metrics endpoint
certmanager_certificate_ready_status{name="metadata-nats-credential"}
certmanager_certificate_renewal_timestamp{name="metadata-nats-credential"}
```

**Grafana Dashboard:**

```json
{
  "dashboard": "OpenBao Integration Metrics",
  "panels": [
    {
      "title": "Secret-ID Rotation Rate",
      "query": "rate(vault_secret_id_rotation_success[5m])",
      "target": "1 rotation per 5 minutes"
    },
    {
      "title": "Vault Request Latency",
      "query": "histogram_quantile(0.95, vault_request_duration_seconds)",
      "threshold": "< 100ms"
    },
    {
      "title": "Token Age",
      "query": "vault_token_age_seconds",
      "alert": "> 86400 (1 day)"
    },
    {
      "title": "Certificate Expiry",
      "query": "time() - certmanager_certificate_renewal_timestamp",
      "alert": "> 10800 (3 hours without renewal)"
    }
  ]
}
```

---

## 11. Comparison with Alternative Approaches

| Aspect | Kubernetes Secrets | External Secrets Operator | OpenBao Agent Sidecar (SecureTransport) |
|--------|-------------------|---------------------------|----------------------------------------|
| **Secret rotation** | ❌ Manual only | ✅ Automated (polling) | ✅ Automated (push + rotation) |
| **Encryption at rest** | ⚠️ etcd encryption (optional) | ⚠️ Depends on backend | ✅ OpenBao encryption |
| **Audit logging** | ❌ No native audit | ⚠️ Limited (depends on backend) | ✅ Full audit trail |
| **Dynamic secrets** | ❌ Static only | ⚠️ Depends on backend | ✅ Dynamic generation |
| **PKI integration** | ❌ Manual cert creation | ⚠️ Via cert-manager | ✅ Native PKI + cert-manager |
| **Fine-grained permissions** | ⚠️ Namespace-level RBAC | ✅ Backend-specific | ✅ Policy-based (path-level) |
| **Secret-id rotation** | ❌ N/A | ❌ No (uses static creds) | ✅ Every 5 minutes |
| **Token management** | ❌ N/A | ⚠️ Long-lived tokens | ✅ Auto-renewal (1-day TTL) |
| **Zero-trust** | ❌ Secrets stored in cluster | ⚠️ Partial | ✅ No long-lived credentials |
| **Complexity** | Low | Medium | High |
| **Operational overhead** | Low | Medium | High |
| **Security posture** | Low | Medium | High |

**When to Use Each:**

**Kubernetes Secrets:**
- ✅ Simple applications with static secrets
- ✅ Development/testing environments
- ❌ Production systems with compliance requirements

**External Secrets Operator:**
- ✅ Migrating from Kubernetes Secrets to external vault
- ✅ Multi-cloud environments
- ❌ Need for dynamic secret generation
- ❌ Frequent secret rotation requirements

**OpenBao Agent Sidecar:**
- ✅ Production systems with strict security requirements
- ✅ Post-quantum cryptography needs
- ✅ Dynamic certificate generation
- ✅ Frequent rotation requirements
- ❌ Resource-constrained environments (Agent overhead)

---

## 12. Conclusion

The OpenBao integration via Agent sidecar pattern demonstrates that **enterprise-grade secrets management** is achievable in Kubernetes without compromising on security or operational simplicity.

**Key Achievements:**

1. **Zero long-lived credentials** - Services never handle AppRole credentials directly
2. **Automatic rotation** - Secret-id rotated every 5 minutes, tokens renewed automatically
3. **PKI integration** - Certificates issued dynamically via cert-manager with automatic renewal
4. **Self-healing** - Agent handles authentication failures and token renewal transparently
5. **Policy-based access** - Fine-grained permissions per service and secret path
6. **Audit trail** - All secret access logged in OpenBao for compliance
7. **Dynamic secrets** - ServiceBundles and CaBundles generated on-demand

**Trade-offs Accepted:**

- ✅ **Additional container overhead** (bao-agent sidecar) for security isolation
- ✅ **Complexity** (Agent configuration, policy management) for zero-trust security
- ✅ **Network dependency** (OpenBao availability) for centralized secrets management
- ✅ **Learning curve** (Vault concepts, policies) for enterprise-grade security

**Production Readiness:**

| Aspect | Status | Notes |
|--------|--------|-------|
| **Functional correctness** | ✅ Tested | Secret-id rotation verified over 24+ hours |
| **Security** | ✅ Verified | AppRole credentials isolated, tokens short-lived |
| **Reliability** | ✅ Proven | Agent auto-recovery, token renewal working |
| **Performance** | ✅ Acceptable | <10ms overhead for Agent proxy |
| **Observability** | ✅ Instrumented | Metrics, logging, health checks implemented |
| **Documentation** | ✅ Complete | Configuration, troubleshooting, best practices |

**The Bottom Line:**

The Agent sidecar pattern provides **the best security posture** for Kubernetes secrets management by:
- **Eliminating long-lived credentials** from application containers
- **Automating rotation** without application restarts
- **Enforcing least-privilege access** via policies
- **Providing audit trails** for compliance

The operational complexity is justified for production systems requiring **zero-trust security**, **compliance**, and **post-quantum cryptography**.

---

**What's Next:**

- **Blog 6**: NATS messaging with short-lived keys and topic permissions

---

**Explore the code:**
- [VaultAppRoleSecretRotationVert.java](https://github.com/t-snyder/010-SecureTransport/blob/main/svc-core/src/main/java/core/verticle/VaultAppRoleSecretRotationVert.java)
- [VaultAccessHandler.java](https://github.com/t-snyder/010-SecureTransport/blob/main/svc-core/src/main/java/core/handler/VaultAccessHandler.java)
- [MetadataServiceVert.java](https://github.com/t-snyder/010-SecureTransport/blob/main/svc-metadata/src/main/java/verticle/MetadataServiceVert.java)
- [MetadataKeyExchangeVert.java](https://github.com/t-snyder/010-SecureTransport/blob/main/svc-metadata/src/main/java/verticle/MetadataKeyExchangeVert.java)
- [Step-05-OpenBao-ConfigureAuthAndIssuers.sh](https://github.com/t-snyder/010-SecureTransport/blob/main/deploy/scripts/Step-05-OpenBao-ConfigureAuthAndIssuers.sh)

---

**License:** Apache 2.0  
**Repository:** https://github.com/t-snyder/010-SecureTransport  
**Author:** t-snyder  
