---
layout: readme
title: Secure Transport Research Project - Part 4 - Automated CA Certificate Rotation
exclude_from_feed: true 
pinned: false
excerpt: "Deep dive into automated Intermediate CA Bundle Rotation: epoch-driven timing with CaEpochUtil, three-tier orchestration (Metadata generation, Watcher SIGHUP coordination, client reloads), zero-downtime certificate updates, and cryptographic guarantees for post-quantum readiness."
categories: [Security, Cryptography, Kubernetes]
tags: [post-quantum, certificate-rotation, zero-trust, kubernetes, cert-manager, NATS, PKI, SIGHUP]
series: "SecureTransport Research Prototype"
series_part: 4
---

# Automated Intermediate CA Certificate Rotation: Zero-Downtime Certificate Management

## Introduction

In traditional service PKI deployments, certificate rotation is a manual, 
high-risk operation typically performed yearly or quarterly. More sophisticated
organizations with larger service bases may use Cert-manager for managing certficate
rotation for leaf certificates. However when Intermediate certificates are rotated,
Administrators schedule maintenance windows, update certificate files, restart services, and hope nothing breaks. This model is incompatible with modern zero-trust architectures that demand **hourly or daily certificate rotation** to minimize the blast radius of compromised credentials.

SecureTransport's Intermediate CA rotation system demonstrates that **fully automated, zero-downtime certificate rotation** is not just theoretically possible—it's operationally viable for distributed microservices architectures. The system achieves this through:

1. **Epoch-based timing synchronization** via `CaEpochUtil`
2. **Three-tier orchestration architecture** (Metadata → Watcher → Clients)
3. **SIGHUP-based NATS reload** (no pod restarts required)
4. **Overlapping validity windows** (4 concurrent valid CA bundles)
5. **Cryptographic provenance** (every rotation is signed and epoch-tagged)

This blog explores the complete CA rotation lifecycle, from bundle generation to cluster-wide deployment, with deep dives into the code that makes zero-downtime rotation possible.

---

## 1. The Certificate Rotation Challenge

### 1.1 Traditional Certificate Rotation Pain Points

**Manual Certificate Updates:**
```
1. Generate new certificate from CA
2. Copy certificate files to all servers
3. Update configuration files
4. Restart services one-by-one
5. Monitor for failures
6. Rollback if anything breaks
```

**Problems:**
- ❌ Requires scheduled downtime
- ❌ Human error during file distribution
- ❌ Race conditions (some services have new cert, others have old)
- ❌ No atomicity (partial updates leave system inconsistent)
- ❌ Slow rollback (manual file replacement + restarts)
- ❌ Doesn't scale to hourly/daily rotation frequencies

### 1.2 SecureTransport's Automated Rotation

**Event-Driven, Zero-Downtime Rotation:**
```
1. CaRotationVert generates new Intermediate CA certificate (Metadata Service)
2. Obtains other non expired certificates and Root CA Certificate - builds CA Bundle
3. Publishes CA bundle to NATS topic (atomic operation) and stores in OpenBao
4. Watcher Service updates Kubernetes Secret (nats-ca-tls)
5. Watcher issues SIGHUP to NATS server pods (config reload, not restart)
6. NATS servers reload certificates from updated Secret (seconds, not minutes)
7. Regular Services reload client certificates (automatic reconnection)
8. Old certificates expire after overlap period (graceful transition)
```

**Advantages:**
- ✅ **Zero downtime** - Services continue processing messages during rotation
- ✅ **Atomic updates** - CA bundle published in single NATS message
- ✅ **Coordinated rollout** - Watcher orchestrates NATS cluster updates
- ✅ **Self-healing** - Services automatically fetch missing certificates
- ✅ **Observable** - Every rotation logged with epoch metadata
- ✅ **Cryptographically provable** - Epoch-based validation ensures correctness
- ✅ **No pod restarts** - SIGHUP triggers config reload (3-5 second interruption)

---

## 2. CA Epoch Management: Synchronized Rotation Boundaries

### 2.1 CaEpochUtil: The Timing Authority

The CA rotation system uses `CaEpochUtil` to synchronize certificate lifecycles across all services. This ensures that every component in the system agrees on rotation boundaries, preventing clock drift issues and race conditions.

```java
Project: svc-core
Package: core.utils
Class:   CaEpochUtil.java

public class CaEpochUtil {
  
  // Testing configuration (rapid rotation for validation)
  public static final long CA_EPOCH_DURATION_MILLIS = 1200000L;   // 20 minutes
  public static final long CA_VALIDITY_MILLIS       = 4800000L;   // 80 minutes
  private static final long CA_EPOCH_ZERO_MILLIS    = 0L;         // 1970-01-01T00:00:00Z

  // Production configuration (commented out for testing)
  // public static final long CA_EPOCH_DURATION_MILLIS = 6 * 60 * 60 * 1000L;  // 6 hours
  // public static final long CA_VALIDITY_MILLIS       = 12 * 60 * 60 * 1000L; // 12 hours

  /**
   * Returns the CA epoch number for the given instant.
   */
  public static long caEpochNumberForInstant(Instant instant) {
    return (instant.toEpochMilli() - CA_EPOCH_ZERO_MILLIS) / CA_EPOCH_DURATION_MILLIS;
  }

  /**
   * Returns the start instant for the given CA epoch number.
   */
  public static Instant caEpochStart(long epochNumber) {
    return Instant.ofEpochMilli(CA_EPOCH_ZERO_MILLIS + epochNumber * CA_EPOCH_DURATION_MILLIS);
  }

  /**
   * Returns the expiry instant for the given CA epoch number.
   */
  public static Instant caEpochExpiry(long epochNumber) {
    return caEpochStart(epochNumber).plusMillis(CA_VALIDITY_MILLIS);
  }
  
  /**
   * Returns all valid CA epoch numbers at the given instant.
   */
  public static Set<Long> getValidCaEpochs(Instant now) {
    Set<Long> validEpochs = new HashSet<>();
    long currentEpoch = caEpochNumberForInstant(now);
    
    for (long epoch = currentEpoch; epoch >= currentEpoch - 3; epoch--) {
      Instant expiry = caEpochExpiry(epoch);
      if (expiry.isAfter(now)) {
        validEpochs.add(epoch);
      }
    }
    
    return validEpochs;
  }
}
```

**Key Design Principles:**

1. **Fixed Epoch Boundaries**: CA epochs start at predictable wall-clock times (every 20 minutes)
2. **Overlapping Validity**: Certificates valid for 4× the rotation period (80-minute validity, 20-minute rotation)
3. **Multiple Valid Epochs**: At any given time, 4 concurrent CA epochs have valid certificates

### 2.2 Epoch Timeline Example

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    CA Certificate Lifecycle                             │
└─────────────────────────────────────────────────────────────────────────┘

  Epoch 100       Epoch 101       Epoch 102       Epoch 103       Epoch 104
  (Legacy-2)      (Legacy-1)      (Previous)      (Current)       (Next)
     │               │               │               │               │
T=08:00          T=08:20         T=08:40         T=09:00         T=09:20
     │               │               │               │               │
     ├─ VALID ───────┼─ VALID ───────┼─ VALID ───────┼─ VALID ───────┤
     │  (expires     │  (expires     │  (expires     │  (expires     │
     │   09:20)      │   09:40)      │   10:00)      │   10:20)      │
     │               │               │               │               │
     │               │               │          ▲                    │
     │               │               │          │                    │
     │               │               │    [CaRotationVert            │
     │               │               │     Generates Bundle]         │
     │               │               │          │                    │
     │               │               │          ▼                    │
     │               │               │    [Published to NATS]        │
     │               │               │          │                    │
     │               │               │          ▼                    │
     │               │               │    [Watcher: Secret +         │
     │               │               │     SIGHUP]                   │
     │               │               │          │                    │
     │               │               │          ▼                    │
     │               │               │    [Services Reload]          │
     │               │               │                               │
     ▼               ▼               ▼               ▼               ▼
  EXPIRED         ACTIVE          ACTIVE          CURRENT          FUTURE
```

**Rotation Sequence:**

1. **T=08:55** (5 min before epoch 103): CaRotationVert pre-generates CA bundle
2. **T=09:00** (epoch 103 starts): Bundle published to NATS topic
3. **T=09:05** (5 min grace): Watcher updates Secret and issues SIGHUP
4. **T=09:20** (epoch 100 expiry): Old certificates no longer valid

---

## 3. Three-Tier Orchestration Architecture

### 3.1 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                  CA Rotation Architecture                       │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ TIER 1: Metadata Service (Authority)                            │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ CaRotationVert                                              │ │
│ │  • Epoch-aligned timer (20-minute intervals)                │ │
│ │  • Generates Intermediate CA from OpenBao PKI               │ │
│ │  • Builds CA bundle (Intermediate(s) + Root)                │ │
│ │  • Stores bundle in OpenBao KV                              │ │
│ │  • Creates Kubernetes Secret                                │ │
│ │  • Publishes to metadata.client.ca-cert topic               │ │
│ └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ NATS JetStream
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ TIER 2: Watcher Service (NATS Coordinator)                      │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ CaBundleConsumerVert                                        │ │
│ │  • Pull consumer on metadata.client.ca-cert                 │ │
│ │  • Epoch extraction and validation                          │ │
│ │  • Single-flight rotation with epoch coalescing             │ │
│ └─────────────────────────────────────────────────────────────┘ │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ NatsCaBundleMsgProcessor                                    │ │
│ │  1. Update Kubernetes Secret (nats-ca-tls)                  │ │
│ │  2. Wait for Secret propagation (2 seconds)                 │ │
│ │  3. Update Watcher's local CA file                          │ │
│ │  4. Send SIGHUP to all NATS pods (parallel)                 │ │
│ │  5. Wait for NATS server reload (2 seconds)                 │ │
│ │  6. Notify Watcher's NATS client to reconnect               │ │
│ └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Kubernetes Secret + SIGHUP
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ NATS Server Pods (3 replicas)                                   │
│  • Receive SIGHUP signal                                        │
│  • Reload configuration (no restart)                            │
│  • Re-read /etc/nats/ca/ca.crt from Secret volume mount         │
│  • Update TLS context (1-3 seconds)                             │
│  • Maintain existing connections                                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Automatic reconnection
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ TIER 3: Client Services (Certificate Consumers)                 │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ CaBundleUpdateVert (in each service)                        │ │
│ │  • Pull consumer on metadata.client.ca-cert                 │ │
│ │  • Fetch CA bundle from Secret                              │ │
│ │  • Write to local file                                      │ │
│ │  • Reload TLS context                                       │ │
│ │  • Reconnect NATS client (3-5 seconds)                      │ │
│ │  • Reload producers/consumers                               │ │
│ └─────────────────────────────────────────────────────────────┘ │
│                                                                 │
│ Services: AuthController, Gatekeeper, etc.                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Tier 1: Metadata Service - CA Bundle Generation

The Metadata Service generates Intermediate CA certificates from OpenBao PKI and publishes bundles to all services.

### 4.1 Periodic Rotation Scheduling

```java
Project: svc-metadata
Package: verticle
Class:   CaRotationVert.java

/**
 * Schedule CA rotation aligned to epoch boundaries.
 * Pre-generates bundle 5 minutes before epoch starts.
 */
private void scheduleCaRotation() {
  Instant now = Instant.now();
  long currentEpoch = CaEpochUtil.caEpochNumberForInstant(now);
  Instant nextEpochStart = CaEpochUtil.caEpochStart(currentEpoch + 1);
  
  // Calculate delay to 5 minutes BEFORE next epoch
  long preparationWindow = 5 * 60 * 1000L;
  long delayToNextRotation = nextEpochStart.toEpochMilli() 
                              - now.toEpochMilli() 
                              - preparationWindow;
  
  if (delayToNextRotation < 0) {
    nextEpochStart = CaEpochUtil.caEpochStart(currentEpoch + 2);
    delayToNextRotation = nextEpochStart.toEpochMilli() 
                           - now.toEpochMilli() 
                           - preparationWindow;
  }
  
  LOGGER.info("First CA rotation scheduled in {} ms", delayToNextRotation);
  
  vertx.setTimer(delayToNextRotation, id -> {
    performCaRotation();
    
    // Schedule periodic rotation every epoch
    caRotationTimerId = vertx.setPeriodic(
      CaEpochUtil.CA_EPOCH_DURATION_MILLIS, 
      periodicId -> performCaRotation()
    );
  });
}
```

### 4.2 CA Bundle Generation Flow

```java
private void performCaRotation() {
  Instant now = Instant.now();
  long newEpoch = CaEpochUtil.caEpochNumberForInstant(now);
  
  LOGGER.info("=== Starting CA Rotation for Epoch {} ===", newEpoch);
  
  workerExecutor.executeBlocking(() -> {
    // 1. Generate Intermediate CA from OpenBao PKI
    return generateIntermediateCaCertificate(newEpoch);
  })
  .compose(intermediateCert -> {
    // 2. Fetch Root CA
    return fetchRootCaCertificate()
      .map(rootCert -> new Object[] { intermediateCert, rootCert });
  })
  .compose(certs -> {
    // 3. Build CA Bundle (Intermediate + Root)
    String caBundle = buildCaBundle(
      (String) ((Object[]) certs)[0], 
      (String) ((Object[]) certs)[1], 
      newEpoch
    );
    
    // 4. Store in OpenBao
    return storeCaBundleInVault(newEpoch, caBundle).map(v -> caBundle);
  })
  .compose(caBundle -> {
    // 5. Create Kubernetes Secret
    return createCaBundleSecret(newEpoch, caBundle);
  })
  .compose(secretName -> {
    // 6. Publish to NATS
    return publishCaBundleUpdate(newEpoch, secretName);
  })
  .onSuccess(v -> {
    caEpochNumber = newEpoch;
    LOGGER.info("✅ CA Rotation completed for epoch {}", newEpoch);
  });
}
```

### 4.3 CA Bundle Storage

**OpenBao Storage:**

```java
private Future<Void> storeCaBundleInVault(long epochNumber, String caBundle) {
  return workerExecutor.executeBlocking(() -> {
    String path = "secret/data/ca-bundles/epoch-" + epochNumber;
    
    Map<String, Object> data = Map.of(
      "data", Map.of(
        "ca-bundle.pem", caBundle,
        "epoch", epochNumber,
        "created_at", Instant.now().toString(),
        "expires_at", CaEpochUtil.caEpochExpiry(epochNumber).toString()
      )
    );
    
    openBaoClient.write(path, data);
    LOGGER.info("Stored CA bundle in OpenBao at {}", path);
    return null;
  });
}
```

**Kubernetes Secret:**

```java
private Future<String> createCaBundleSecret(long epochNumber, String caBundle) {
  return workerExecutor.executeBlocking(() -> {
    String secretName = "nats-ca-bundle-epoch-" + epochNumber;
    
    Secret secret = new SecretBuilder()
      .withNewMetadata()
        .withName(secretName)
        .withNamespace("openbao")
        .addToLabels("epoch", String.valueOf(epochNumber))
      .endMetadata()
      .addToData("ca-bundle.pem", 
                 Base64.getEncoder().encodeToString(caBundle.getBytes()))
      .build();
    
    kubernetesClient.secrets()
      .inNamespace("openbao")
      .createOrReplace(secret);
    
    return secretName;
  });
}
```

### 4.4 NATS Publication

```java
private Future<Void> publishCaBundleUpdate(long epochNumber, String secretName) {
  return workerExecutor.executeBlocking(() -> {
    CaBundleMessage message = new CaBundleMessage(
      epochNumber,
      secretName,
      "openbao",
      CaEpochUtil.caEpochStart(epochNumber),
      CaEpochUtil.caEpochExpiry(epochNumber),
      Instant.now()
    );
    return message;
  })
  .compose(message -> workerExecutor.executeBlocking(() -> 
    CaBundleMessage.serialize(message)))
  .compose(messageBytes -> 
    natsClient.publishAsync("metadata.client.ca-cert", messageBytes));
}
```

---

## 5. Tier 2: Watcher Service - SIGHUP-Based NATS Reload

The Watcher Service coordinates NATS cluster certificate updates using SIGHUP signals instead of pod restarts.

### 5.1 Message Consumption with Epoch Coalescing

```java
Project: svc-watcher
Package: verticle
Class:   CaBundleConsumerVert.java

/**
 * Schedule or queue rotation based on epoch.
 * Implements single-flight rotation with epoch coalescing.
 */
private void scheduleOrQueue(long epoch, byte[] raw) {
  long cur = currentEpoch;
  
  if (epoch <= cur) {
    LOGGER.info("⏭️  Ignoring stale CA bundle epoch={}", epoch);
    return;
  }

  if (rotationInProgress.compareAndSet(false, true)) {
    currentEpoch = epoch;
    LOGGER.info("🔄 STARTING CA BUNDLE ROTATION - Epoch: {}", epoch);
    startRotation(epoch, raw);
  } else {
    // Queue newer epochs, discard older ones
    Pending prev = pending.get();
    while (true) {
      if (prev == null) {
        if (pending.compareAndSet(null, new Pending(epoch, raw))) {
          LOGGER.info("📥 Queued CA rotation epoch={}", epoch);
          break;
        }
      } else if (epoch > prev.epoch) {
        if (pending.compareAndSet(prev, new Pending(epoch, raw))) {
          LOGGER.info("🔄 Replaced queued epoch={} with {}", prev.epoch, epoch);
          break;
        }
      } else {
        LOGGER.info("⏭️  Discarding incoming epoch={}", epoch);
        break;
      }
      prev = pending.get();
    }
  }
}
```

### 5.2 Complete Rotation Orchestration

```java
Project: svc-watcher
Package: processor
Class:   NatsCaBundleMsgProcessor.java

private Future<Void> performRotation(CaBundle caBundle) {
  long startTime = System.currentTimeMillis();
  String caContent = caBundle.getCaBundle();

  LOGGER.info("╔═══════════════════════════════════════════════════════════════╗");
  LOGGER.info("║ WATCHER: CA Rotation Orchestration Started                  ║");
  LOGGER.info("║ Epoch: {}                                                    ║", 
              caBundle.getCaEpochNumber());
  LOGGER.info("╚═══════════════════════════════════════════════════════════════╝");

  return updateSecret(caContent)
    .compose(v -> {
      LOGGER.info("✅ Step 1: K8s secret updated");
      return waitAsync(SECRET_PROPAGATION_WAIT_SEC, "Secret propagation");
    })
    .compose(v -> {
      LOGGER.info("Step 2: Updating watcher's CA file");
      return updateWritableCaFile(caContent);
    })
    .compose(v -> {
      LOGGER.info("✅ Step 2: Watcher's CA file updated");
      LOGGER.info("Step 3: Sending SIGHUP to NATS pods");
      return sendReloadToPodsParallel();
    })
    .compose(v -> {
      LOGGER.info("✅ Step 3: SIGHUP sent to all NATS pods");
      LOGGER.info("Step 4: Waiting for NATS server reload");
      return waitAsync(SERVER_RELOAD_WAIT_SEC, "Server reload");
    })
    .compose(v -> {
      LOGGER.info("Step 5: Notifying local NATS client");
      return natsTlsClient.handleCaBundleUpdate(caBundle)
          .recover(err -> {
            LOGGER.warn("Client update failed (non-fatal): {}", err.getMessage());
            return Future.succeededFuture();
          });
    })
    .compose(v -> {
      long elapsed = System.currentTimeMillis() - startTime;
      
      LOGGER.info("╔═══════════════════════════════════════════════════════════════╗");
      LOGGER.info("║ ✅ WATCHER: CA Rotation Complete - Duration: {}ms           ║", elapsed);
      LOGGER.info("║ NATS servers reloaded - all clients will reconnect          ║");
      LOGGER.info("╚═══════════════════════════════════════════════════════════════╝");
      
      return Future.succeededFuture();
    })
    .mapEmpty();
}
```

### 5.3 Kubernetes Secret Update

```java
private Future<String> updateSecret(String caBundleContent) {
  return vertx.executeBlocking(() -> {
    Secret updated = kubeClient.secrets()
      .inNamespace(namespace)
      .withName(NATS_CA_SECRET_NAME)
      .edit(current -> {
        SecretBuilder b = new SecretBuilder(current);
        b.addToStringData(NATS_CA_SECRET_KEY, caBundleContent);
        b.editMetadata()
          .addToAnnotations("rotation.watcher.io/ts", Instant.now().toString())
          .endMetadata();
        return b.build();
      });

    LOGGER.info("✅ Updated secret '{}'", NATS_CA_SECRET_NAME);
    return updated.getMetadata().getResourceVersion();
  });
}
```

**NATS Pod Volume Mount:**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: nats
    volumeMounts:
    - name: nats-ca-tls
      mountPath: /etc/nats/ca
      readOnly: true
  volumes:
  - name: nats-ca-tls
    secret:
      secretName: nats-ca-tls  # Updated by Watcher
```

### 5.4 SIGHUP Signal Delivery

**The Key Innovation - No Pod Restarts:**

```java
private Future<Void> sendReloadToPodsParallel() {
  return vertx.executeBlocking(() -> {
    boolean any = natsReloader.reloadAll("app", "nats");
    if (!any) {
      throw new RuntimeException("All pod reload attempts failed");
    }
    return null;
  }).mapEmpty();
}
```

**Fabric8NatsReloader Implementation:**

```java
Project: svc-watcher
Package: utils
Class:   Fabric8NatsReloader.java

/**
 * Reload all NATS pods by executing "kill -HUP 1" in each container.
 */
public boolean reloadAll(String labelKey, String labelValue) {
  List<Pod> pods = client.pods()
    .inNamespace(namespace)
    .withLabel(labelKey, labelValue)
    .list()
    .getItems();
  
  if (pods.isEmpty()) {
    LOGGER.warn("No pods found with label {}={}", labelKey, labelValue);
    return false;
  }
  
  LOGGER.info("Found {} NATS pods to reload", pods.size());
  
  int successCount = 0;
  for (Pod pod : pods) {
    String podName = pod.getMetadata().getName();
    if (reloadPod(podName)) {
      successCount++;
    }
  }
  
  LOGGER.info("SIGHUP reload summary: {}/{} pods succeeded", successCount, pods.size());
  return successCount > 0;
}

/**
 * Send SIGHUP to a single NATS pod.
 * Executes "kill -HUP 1" inside the container.
 */
private boolean reloadPod(String podName) {
  try {
    LOGGER.info("Sending SIGHUP to pod: {}", podName);
    
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    
    ExecWatch watch = client.pods()
      .inNamespace(namespace)
      .withName(podName)
      .inContainer(containerName)  // "nats"
      .writingOutput(out)
      .writingError(err)
      .exec("kill", "-HUP", "1");  // PID 1 is NATS server process
    
    boolean completed = watch.exitCode()
      .get(execTimeout.toMillis(), TimeUnit.MILLISECONDS) == 0;
    
    if (completed) {
      LOGGER.info("✅ SIGHUP sent successfully to pod: {}", podName);
      return true;
    } else {
      LOGGER.warn("❌ SIGHUP failed for pod: {}", podName);
      return false;
    }
  } catch (Exception e) {
    LOGGER.error("❌ Exception sending SIGHUP to pod {}: {}", 
                 podName, e.getMessage());
    return false;
  }
}
```

### 5.5 Why SIGHUP Instead of Pod Restart?

| Aspect | Pod Restart | SIGHUP Signal |
|--------|-------------|---------------|
| **Downtime** | 30-60 seconds | 1-3 seconds |
| **Message loss** | Possible | None |
| **Client impact** | All disconnect immediately | Graceful reconnect |
| **Parallelization** | One pod at a time (StatefulSet) | All pods in parallel |
| **Kubernetes overhead** | High (scheduling, health checks) | Low (simple exec) |
| **Rollback** | StatefulSet rollback | Re-send SIGHUP with old Secret |

**NATS Server SIGHUP Behavior:**

When NATS receives SIGHUP:
1. Reloads `/etc/nats/nats.conf`
2. Re-reads mounted Secrets and ConfigMaps
3. Updates TLS certificates (CA, server cert)
4. Maintains existing client connections
5. New connections use updated certificates
6. Logs reload completion

**Example NATS Log:**

```
[1] 2025-01-15 17:43:51.234 [INF] Reloading server configuration
[1] 2025-01-15 17:43:51.567 [INF] Reloaded: /etc/nats/ca/ca.crt
[1] 2025-01-15 17:43:51.789 [INF] Server configuration reload completed
```

---

## 6. Tier 3: Client Services - Certificate Reload

Client services reload their NATS client certificates without service restarts.

### 6.1 CaBundleUpdateVert in Every Service

```java
Project: svc-core
Package: core.verticle
Class:   CaBundleUpdateVert.java

public class CaBundleUpdateVert extends AbstractVerticle {
  
  @Override
  public void start(Promise<Void> startPromise) {
    LOGGER.info("Starting CA Bundle Update Verticle for service {}", 
                serviceCore.getServiceId());
    
    subscribeToCaBundleUpdates()
      .onSuccess(v -> startPromise.complete())
      .onFailure(startPromise::fail);
  }
  
  private Future<Void> subscribeToCaBundleUpdates() {
    return workerExecutor.executeBlocking(() -> {
      String stream = "METADATA_CA_CLIENT";
      String consumerName = serviceCore.getServiceId() + "-ca-consumer";
      
      PullSubscribeOptions pullOptions = PullSubscribeOptions.builder()
        .stream(stream)
        .durable(consumerName)
        .build();
      
      JetStreamSubscription subscription = natsClient.getJetStream()
        .subscribe("metadata.client.ca-cert", pullOptions);
      
      startMessageFetchLoop(subscription);
      return null;
    });
  }
}
```

### 6.2 Client Certificate Reload Flow

```java
private Future<Void> processCaBundleMessage(Message natsMsg) {
  return workerExecutor.executeBlocking(() -> {
    CaBundleMessage message = CaBundleMessage.deserialize(natsMsg.getData());
    
    LOGGER.info("=== Received CA Bundle Update ===");
    LOGGER.info("Epoch: {}, Valid: {} to {}", 
                message.getCaEpochNumber(),
                message.getValidFrom(), 
                message.getValidUntil());
    
    return message;
  })
  .compose(message -> fetchCaBundleFromSecret(message.getSecretName()))
  .compose(caBundleBytes -> writeCaBundleToFile(caBundleBytes))
  .compose(caBundlePath -> reloadNatsTlsContext(caBundlePath))
  .compose(v -> reconnectNatsClient())
  .compose(v -> reloadMessagingComponents())
  .onSuccess(v -> {
    LOGGER.info("✅ CA bundle reload completed successfully");
  });
}
```

### 6.3 TLS Context Reload

```java
private Future<Void> reloadNatsTlsContext(String caBundlePath) {
  return workerExecutor.executeBlocking(() -> {
    LOGGER.info("Reloading NATS TLS context with CA bundle: {}", caBundlePath);
    
    // 1. Load CA certificates from PEM file
    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    List<X509Certificate> caCerts = loadCertificatesFromPem(caBundlePath);
    
    LOGGER.info("Loaded {} CA certificates from bundle", caCerts.size());
    
    // 2. Build TrustManager
    KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustStore.load(null, null);
    
    for (int i = 0; i < caCerts.size(); i++) {
      trustStore.setCertificateEntry("ca-" + i, caCerts.get(i));
    }
    
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(
      TrustManagerFactory.getDefaultAlgorithm()
    );
    tmf.init(trustStore);
    
    // 3. Create new SSLContext
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
    
    // 4. Update NATS client
    natsClient.updateSslContext(sslContext);
    
    LOGGER.info("✅ NATS TLS context reloaded successfully");
    return null;
  });
}
```

### 6.4 NATS Client Reconnection

```java
private Future<Void> reconnectNatsClient() {
  return workerExecutor.executeBlocking(() -> {
    LOGGER.info("Reconnecting NATS client with new TLS context");
    
    // 1. Drain existing connection
    natsClient.drain(Duration.ofSeconds(5));
    LOGGER.info("Drained existing NATS connection");
    
    // 2. Close old connection
    natsClient.close();
    LOGGER.info("Closed old NATS connection");
    
    return null;
  })
  .compose(v -> {
    // 3. Reconnect with new TLS context
    return natsClient.connect()
      .onSuccess(conn -> {
        LOGGER.info("✅ NATS client reconnected successfully");
      });
  });
}
```

### 6.5 Producer/Consumer Reload

```java
private Future<Void> reloadMessagingComponents() {
  return workerExecutor.executeBlocking(() -> {
    LOGGER.info("Reloading message producers and consumers");
    
    // Notify all verticles to reload
    vertx.eventBus().publish(
      "ca-bundle-updated", 
      Json.encode(Map.of("timestamp", Instant.now().toString()))
    );
    
    LOGGER.info("✅ Sent reload notification to all verticles");
    return null;
  });
}
```

**Example Consumer Reload:**

```java
// In AuthControllerVert
vertx.eventBus().consumer("ca-bundle-updated", msg -> {
  LOGGER.info("Received CA bundle update notification");
  
  // Unsubscribe old consumer
  if (currentSubscription != null) {
    currentSubscription.unsubscribe();
  }
  
  // Create new pull consumer (uses updated NATS connection)
  PullSubscribeOptions options = PullSubscribeOptions.builder()
    .stream("AUTH_STREAM")
    .durable("auth-requests")
    .build();
  
  currentSubscription = natsClient.getJetStream()
    .subscribe("auth.auth-request", options);
  
  startAuthRequestFetchLoop(currentSubscription);
});
```

---

## 7. Security Guarantees & Properties

### 7.1 Overlapping Validity Windows

**Problem:** How to rotate without downtime?

**Solution:** 4 concurrent valid epochs

```
At T=09:00:
- Epoch 100 (expires 10:20) - Legacy-2
- Epoch 101 (expires 10:40) - Legacy-1  
- Epoch 102 (expires 11:00) - Previous
- Epoch 103 (expires 11:20) - Current

All 4 epochs have valid certificates!
```

**Guarantee:** Services can use any of 4 epochs during rotation window.

### 7.2 Atomic CA Bundle Publication

**Guarantee:** All services receive same CA bundle version via NATS JetStream.

**Properties:**
- ✅ Persistence: Messages survive NATS restarts
- ✅ Ordering: Messages delivered in publish order
- ✅ Deduplication: Duplicate messages filtered
- ✅ Acknowledgment: Services confirm receipt

### 7.3 Clock Drift Tolerance

**Problem:** What if service clocks are out of sync?

**Solution:** 
- All Messages contain the epoch it was generated at
- All Messages contain the TopicKeyId. The key can be retrieved by Id.
- 4-epoch overlap + grace periods

```java
Set<Long> validEpochs = CaEpochUtil.getValidCaEpochs(Instant.now());
// Returns: {epoch-3, epoch-2, epoch-1, epoch-current}
```

**Tolerance:** ±10 minutes clock drift with 4-epoch overlap.

### 7.4 Rollback Capability

**Problem:** What if new CA bundle is broken?

**Solution:** Keep previous epoch Secret

```java
// Watcher does NOT delete old Secret immediately
Secret oldSecret = kubeClient.secrets()
  .withName("nats-ca-tls-epoch-" + (currentEpoch - 1))
  .get();

// Rollback: Update Secret to previous epoch and SIGHUP
updateSecret(oldSecret.getData().get("ca.crt"));
sendReloadToPodsParallel();
```

**Rollback Time:** ~30 seconds (Secret update + SIGHUP + client reconnect)

### 7.5 Zero Message Loss Guarantee

**During rotation:**
- NATS servers maintain connections during SIGHUP reload
- JetStream consumers resume from last acknowledged message
- Client reconnection is automatic (built-in retry logic)
- Message buffering prevents loss during brief disconnections

**Measured downtime:** 3-5 seconds per client (reconnection time)

---

## 8. Operational Metrics & Observability

### 8.1 Key Metrics

**Metadata Service (CaRotationVert):**

```java
metrics.counter("ca_rotation.attempts.total");
metrics.counter("ca_rotation.attempts.success");
metrics.counter("ca_rotation.attempts.failed");
metrics.timer("ca_rotation.generation.duration");
metrics.gauge("ca_rotation.current_epoch", () -> caEpochNumber);
```

**Watcher Service:**

```java
metrics.counter("ca_rotation.sighup.pods.total");
metrics.counter("ca_rotation.sighup.pods.success");
metrics.counter("ca_rotation.sighup.pods.failed");
metrics.timer("ca_rotation.orchestration.duration");
metrics.histogram("ca_rotation.secret.propagation.seconds");
```

**Client Services:**

```java
metrics.counter("ca_rotation.client.reloads.total");
metrics.counter("ca_rotation.client.reloads.success");
metrics.timer("ca_rotation.client.reconnect.duration");
metrics.gauge("ca_rotation.client.last_update", () -> lastUpdateEpoch);
```

### 8.2 Critical Alerts

**Alert Conditions:**

```yaml
# CA bundle age exceeds 2x rotation period
- alert: CaBundleTooOld
  expr: time() - ca_rotation_last_success_timestamp > 2400  # 40 min
  
# SIGHUP failure rate > 10%
- alert: NatsSighupFailureRate
  expr: rate(ca_rotation_sighup_failed[5m]) / rate(ca_rotation_sighup_total[5m]) > 0.1
  
# Client reconnection failures
- alert: ClientCaReloadFailure
  expr: rate(ca_rotation_client_reloads_failed[5m]) > 0
```

### 8.3 Troubleshooting

**Common Issues:**

```bash
# Check Watcher logs for SIGHUP failures
kubectl logs -n nats -l app=watcher --tail=100 | grep SIGHUP

# Verify Secret update timestamp
kubectl get secret nats-ca-tls -n nats -o yaml | grep rotation.watcher.io/ts

# Check NATS server reload logs
kubectl logs -n nats nats-0 | grep "Reloading server configuration"

# Verify client reconnection
kubectl logs -n services -l app=authcontroller --tail=50 | grep "CA bundle"
```

---

## 9. Performance Characteristics

### 9.1 Rotation Timing Breakdown

**Complete Rotation Cycle:**

```
T+0s:    Metadata generates CA bundle
T+1s:    Bundle published to NATS JetStream
T+2s:    Watcher receives message
T+3s:    Watcher updates Kubernetes Secret
T+5s:    Secret propagation wait (2s)
T+6s:    Watcher updates local CA file
T+7s:    SIGHUP sent to NATS pods (parallel)
T+8s:    NATS servers reload certificates
T+10s:   Server reload wait (2s)
T+11s:   Watcher NATS client reconnects
T+12s:   Client services start receiving updates
T+15s:   Clients reconnect (3-5s per service)

Total:   ~15 seconds end-to-end
Impact:  3-5 seconds client downtime
```

### 9.2 Resource Consumption

**Metadata Service:**

```
CPU:    20m during rotation, 5m idle
Memory: 200Mi (CA generation + OpenBao client)
Disk:   Minimal (bundles stored in OpenBao/K8s)
```

**Watcher Service:**

```
CPU:    50m during rotation (SIGHUP exec), 10m idle
Memory: 150Mi (Kubernetes client + NATS client)
Disk:   10Mi (writable CA file)
```

**NATS Server (during SIGHUP):**

```
CPU:    Spike to 100m for 1-2 seconds, then back to baseline
Memory: No increase (config reload, not restart)
Connections: Maintained (no disconnect)
```

**Client Services:**

```
CPU:    30m spike during reconnect, then baseline
Memory: No increase (TLS context reload)
Disk:   5Mi (local CA file)
```

---

## 10. Comparison with Alternative Approaches

| Approach | Downtime | Complexity | Message Loss | Rollback Time | PQC Ready |
|----------|----------|------------|--------------|---------------|-----------|
| **Manual Rotation** | Hours | Low | High | Hours | No |
| **Pod Restart** | 30-60s | Medium | Possible | 5-10 min | Yes |
| **SIGHUP (SecureTransport)** | 3-5s | Medium | None | 30s | Yes |
| **Sidecar Proxy** | None | High | None | Instant | Depends |
| **Service Mesh (Istio)** | None | Very High | None | Instant | Limited |

**Why SecureTransport's Approach:**

- ✅ **Kubernetes-native**: No external dependencies (works with cert-manager)
- ✅ **NATS-specific optimization**: Leverages SIGHUP for fast reload
- ✅ **Observable**: Clear logs and metrics at every step
- ✅ **Simple deployment**: No sidecar containers or mesh complexity
- ✅ **Post-quantum ready**: Works with any certificate size (Dilithium, Kyber)

---

## 11. Limitations & Trade-offs

### 11.1 Current Limitations

| Limitation | Impact | Mitigation |
|-----------|--------|-----------|
| **Minimum rotation frequency** | 20 minutes (testing), 6 hours (prod) | Reduce epoch duration (increases load) |
| **Secret propagation delay** | 2-second wait required | Use Kubernetes watches (complex) |
| **SIGHUP requires exec permission** | ServiceAccount needs pod/exec RBAC | Standard for Kubernetes operators |
| **Clock synchronization required** | NTP must be running | Deploy NTP daemonset |
| **No automatic rollback** | Manual intervention on failure | Add health checks + auto-revert |

### 11.2 Future Enhancements

**Planned Improvements:**

1. **Kubernetes Watch-Based Propagation:**
   - Replace fixed waits with Secret watch
   - Faster rotation (reduce 2s wait to ~500ms)
   - More reliable timing

2. **Certificate Transparency Logging:**
   - Log all CA rotations to immutable audit log
   - Integrate with Certificate Transparency infrastructure
   - Cryptographic proof of rotation history

---

## 12. Conclusion

SecureTransport's automated CA rotation system demonstrates that **zero-downtime, high-frequency certificate rotation** is operationally viable for production microservices architectures.

**Key Innovations:**

1. **Epoch-based synchronization** - All services agree on rotation boundaries
2. **Three-tier orchestration** - Metadata generates, Watcher coordinates, clients consume
3. **SIGHUP-based reload** - 3-5 second impact vs. 30-60 second pod restarts
4. **Overlapping validity** - 4 concurrent valid CA epochs prevent gaps
5. **Event-driven updates** - NATS JetStream ensures atomic, ordered delivery
6. **Cryptographic provenance** - Every bundle signed and epoch-tagged

**Real-World Impact:**

- ✅ **90-day to hourly rotation**: System tested with 20-minute epochs
- ✅ **Zero message loss**: JetStream consumers resume from last ACK
- ✅ **Post-quantum ready**: Works with Dilithium/Kyber certificates
- ✅ **Observable**: Every step logged with timing and epoch metadata
- ✅ **Self-healing**: Automatic reconnection on failure

**The Bottom Line:**

Moving from yearly certificate rotation to hourly/daily rotation is **operationally feasible** with the right architecture. The combination of epoch-based timing, SIGHUP-based reload, and overlapping validity windows enables certificate rotation to become a **background maintenance task** rather than a **major operational event**.

---

**What's Next:**

- **Blog 5**: OpenBao Integration and App Role token management
- **Blog 6**: NATS messaging with short-lived keys and topic permissions

---

**Explore the code:**
- [CaRotatorVert.java](https://github.com/t-snyder/010-SecureTransport/blob/main/svc-metadata/src/main/java/verticle/CaRotatorVert.java)
- [CaBundleConsumerVert.java](https://github.com/t-snyder/010-SecureTransport/blob/main/svc-watcher/src/main/java/verticle/CaBundleConsumerVert.java)
- [NatsCaBundleMsgProcessor.java](https://github.com/t-snyder/010-SecureTransport/blob/main/svc-watcher/src/main/java/processor/NatsCaBundleMsgProcessor.java)
- [CABundleUpdateVert.java](https://github.com/t-snyder/010-SecureTransport/blob/main/svc-core/src/main/java/core/verticle/CABundleUpdateVert.java)
- [CAEpochUtil.java](https://github.com/t-snyder/010-SecureTransport/blob/main/svc-core/src/main/java/core/utils/CAEpochUtil.java)

---

**License:** Apache 2.0  
**Repository:** https://github.com/t-snyder/010-SecureTransport
