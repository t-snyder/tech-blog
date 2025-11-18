---
layout: readme
title: Secure Transport Research Project - Part 3 - Service Authorization
pinned: false
excerpt: "Deep dive into the cryptographic authorization model: how services-acl-configmap defines permissions, how ServiceBundles package cryptographic material with embedded authorization, and how Kyber-based key exchange securely delivers bundles to services."
categories: [Security, Cryptography, Kubernetes]
tags: [post-quantum, authorization, kyber, service-mesh, PKI, cryptography]
series: "SecureTransport Research Prototype"
series_part: 3
---

# ServiceBundle & Key Exchange: Cryptographic Service Authorization in Action

## Introduction

In traditional microservices architectures, service authorization typically relies on centralized policy engines or API gateways that check permissions for every request. This creates scalability bottlenecks, single points of failure, and requires services to trust the authorization infrastructure.

SecureTransport takes a radically different approach: **cryptographic authorization enforcement**. If you don't possess the correct encryption key, you mathematically *cannot* decrypt the message—no policy checks, no central authority, no room for misconfiguration.

This blog explores three critical components that make this work:

1. **Services ACL ConfigMap** - Declarative permission definitions
2. **ServiceBundle** - Cryptographic material + embedded permissions
3. **Key Exchange Protocol** - Secure delivery via Kyber post-quantum cryptography

---

## 1. The Authorization Problem

### 1.1 Traditional Authorization Challenges

**Centralized Policy Enforcement:**
```
Client → API Gateway (checks permissions) → Service A → Service B
                ↑
         Policy Decision Point (PDP)
```

**Problems:**
- Every request requires a policy lookup (latency + load)
- PDP becomes a single point of failure
- Network segmentation doesn't prevent unauthorized access
- Revocation requires coordinated cache invalidation
- No cryptographic guarantee—compromised gateway = full breach

### 1.2 SecureTransport's Cryptographic Authorization

**Decentralized Cryptographic Enforcement:**
```
Metadata Service generates keys based on ACL
                         ↓
ServiceBundle contains ONLY authorized keys
                         ↓
Service A can ONLY decrypt messages for topics it's authorized for
                         ↓
Authorization = Key Possession (mathematically enforced)
```

**Advantages:**
- ✅ No runtime policy checks (authorization verified at key distribution time)
- ✅ Revocation = stop sending new epoch keys (automatic expiration)
- ✅ Cryptographically provable (can't decrypt without the key)
- ✅ Zero-trust by default (every message requires cryptographic proof)
- ✅ Distributed enforcement (no central bottleneck)

---

## 2. Services ACL ConfigMap: Declarative Permissions

### 2.1 The ACL Manifest Structure

The `services-acl-configmap.yaml` defines **which services can publish/subscribe to which topics**:

```
Path: deploy/kube-metadata
name=services-acl-configmap.yaml - deployed as services-acl configmap

apiVersion: v1
kind: ConfigMap
metadata:
  name: services-acl
  namespace: metadata
data:
  acl-manifest.yaml: |
    roles:
      metadata:
        publish:
          - "metadata.bundle-pull.svc-watcher"        # Can respond with Watcher Service Bundle
          - "metadata.bundle-pull.svc-authcontroller" # Can respond with AuthController Service Bundle
          - "metadata.bundle-pull.svc-gatekeeper"     # Can respond with Gatekeeper Service Bundle
          - "metadata.client.ca-cert"                 # Can publish CA Certificate Bundle
        subscribe:
          - "metadata.bundle-pull.svc-metadata"       # Can receive service bundle requests
          - "metadata.client.request"                 # Can receive misc client requests

      watcher:
        publish:
          - "metadata.bundle-pull.svc-metadata"   # Can request Service bundles
        subscribe:
          - "metadata.bundle-pull.svc-watcher"    # Receives Service bundles
          - "metadata.client.ca-cert"             # Receives CA updates

      authcontroller:
        publish:
          - "metadata.bundle-pull.svc-metadata"   # Can request Service bundles
          - "gatekeeper.responder"                # Can respond to gatekeeper
        subscribe:
          - "metadata.bundle-pull.svc-authcontroller"  # Receives Service bundles
          - "metadata.client.ca-cert"                  # Receives CA updates
          - "auth.auth-request"                        # Processes auth requests
      
      gatekeeper:
        publish:
          - "metadata.bundle-pull.svc-metadata"    # Can request Service bundles
          - "auth.auth-request"                    # Sends authentication requests
        subscribe:
          - "metadata.bundle-pull.svc-gatekeeper"  # Receives Service bundles
          - "metadata.client.ca-cert"              # Receives CA bundle updates
          - "gatekeeper.responder"                 # Receives responses
```

### 2.2 Parsing the ACL ConfigMap

The `DeclarativeACLParser` loads this YAML and builds the authorization matrix:

```
Project: svc-metadata
Package: acl
Class:   DeclarativeACLParser.java

public class DeclarativeACLParser {
  
  public Future<ServicesACLMatrix> parseACLFromConfigMap(String yamlContent) {
    return workerExecutor.executeBlocking(() -> {
      Yaml yaml = new Yaml();
      Map<String, Object> aclData = yaml.load(yamlContent);
      
      ServicesACLMatrix matrix = new ServicesACLMatrix();
      Map<String, Object> roles = (Map<String, Object>) aclData.get("roles");
      
      for (Map.Entry<String, Object> roleEntry : roles.entrySet()) {
        String serviceId = roleEntry.getKey();
        Map<String, Object> roleData = (Map<String, Object>) roleEntry.getValue();
        
        // Process publish permissions
        List<String> publishTopics = (List<String>) roleData.get("publish");
        if (publishTopics != null) {
          for (String topic : publishTopics) {
            matrix.addPermission(serviceId, topic, "produce");
          }
        }
        
        // Process subscribe permissions
        List<String> subscribeTopics = (List<String>) roleData.get("subscribe");
        if (subscribeTopics != null) {
          for (String topic : subscribeTopics) {
            matrix.addPermission(serviceId, topic, "consume");
          }
        }
      }
      
      return matrix;
    });
  }
}
```

### 2.3 The ServicesACLMatrix

The parsed data is stored in a concurrent data structure optimized for lookup:

```
Project: svc-metadata
Package: acl
Class:   ServicesACLMatrix.java 

public class ServicesACLMatrix {
  // serviceId -> (topicName -> Set<PermissionType>)
  private final Map<String, Map<String, Set<String>>> serviceTopicPermissions;
  
  // topicName -> Set<serviceId>
  private final Map<String, Set<String>> topicToServices;
  
  /**
   * Returns all topics for which the given service has any permission
   */
  public Set<String> getTopicsForService(String serviceId) {
    Map<String, Set<String>> topics = serviceTopicPermissions.get(serviceId);
    return topics != null ? new HashSet<>(topics.keySet()) : Collections.emptySet();
  }
  
  /**
   * Returns the set of permissions ("produce", "consume") the service has for a topic
   */
  public Set<String> getServiceTopicAccess(String serviceId, String topicName) {
    Map<String, Set<String>> topics = serviceTopicPermissions.get(serviceId);
    return topics != null && topics.containsKey(topicName) 
        ? new HashSet<>(topics.get(topicName)) 
        : Collections.emptySet();
  }
}
```

**Key Design Points:**
- Bi-directional indexing (service→topics AND topic→services)
- Thread-safe concurrent access
- Efficient permission lookups during bundle generation

---

## 3. ServiceBundle: Cryptographic Material + Permissions

### 3.1 What is a ServiceBundle?

A ServiceBundle is a **cryptographically-signed package** containing everything a service needs to participate in secure messaging:

```
Project: svc-core
Package: core.model
Class:   ServiceBundle.java 

public class ServiceBundle {
  private final String serviceId;      // Who this bundle is for
  private final String version;        // Bundle version (timestamp)
  private final long keyEpoch;         // Current key rotation epoch
  private final String updateType;     // "initial", "key-rotation", "acl-update"
  private final Instant createdAt;     // Bundle creation time
  private final String status;         // "current", "expired", "revoked"
  
  // Signing keys (Dilithium) - for this service to sign messages
  private final Map<Long, DilithiumKey> signingKeys;
  
  // Verification keys (Dilithium) - for this service to verify OTHER services
  // serviceId -> (epoch -> public key)
  private final Map<String, Map<Long, DilithiumKey>> verifyKeys;
  
  // Topic encryption keys (AES-256-GCM with HKDF)
  // topicName -> (keyId -> TopicKey)
  private final Map<String, Map<String, TopicKey>> topicKeys;
  
  // Topic permissions with embedded keys
  // topicName -> TopicPermission (includes produce/consume flags + keys)
  private final Map<String, TopicPermission> topicPermissions;
}
```

### 3.2 ServiceBundle Lifecycle

ServiceBundles aren't static—they evolve through a well-defined lifecycle driven by **epoch-based rotation**. Understanding this lifecycle is critical to comprehending how the system maintains security while ensuring zero-downtime operations.

#### 3.2.1 Epoch-Based Time Management

The system uses `KeyEpochUtil` to standardize time-based key rotation across all services:

```
Project: svc-core
Package: core.utils
Class:   KeyEpochUtil.java 

public class KeyEpochUtil {
  // Testing configuration (rapid rotation for validation)
  public static final long EPOCH_DURATION_MILLIS = 900000L;   // 15 minutes
  public static final long KEY_VALIDITY_MILLIS   = 3600000L;  // 1 hour
  private static final long EPOCH_ZERO_MILLIS    = 0L;        // 1970-01-01T00:00:00Z

  // Production configuration (commented out for testing)
  // public static final long EPOCH_DURATION_MILLIS = 3 * 60 * 60 * 1000L;  // 3 hours
  // public static final long KEY_VALIDITY_MILLIS   = 6 * 60 * 60 * 1000L;  // 6 hours

  /**
   * Returns the epoch number for the given instant.
   * Example: Instant at 2025-01-14T08:15:00Z → epoch number 98765
   */
  public static long epochNumberForInstant(Instant instant) {
    return (instant.toEpochMilli() - EPOCH_ZERO_MILLIS) / EPOCH_DURATION_MILLIS;
  }

  /**
   * Returns the start instant for the given epoch number.
   * Example: epoch 98765 → 2025-01-14T08:00:00Z
   */
  public static Instant epochStart(long epochNumber) {
    return Instant.ofEpochMilli(EPOCH_ZERO_MILLIS + epochNumber * EPOCH_DURATION_MILLIS);
  }

  /**
   * Returns the expiry instant for the given epoch number.
   * Keys created in this epoch remain valid until this time.
   */
  public static Instant epochExpiry(long epochNumber) {
    return epochStart(epochNumber).plusMillis(KEY_VALIDITY_MILLIS);
  }
}
```

**Key Design Principles:**

1. **Fixed Epoch Boundaries**: Epochs start at predictable wall-clock times (e.g., every 15 minutes: :00, :15, :30, :45)
2. **Overlapping Validity**: Keys are valid for 4× the rotation period (1 hour validity, 15-minute rotation)
3. **Multiple Valid Epochs**: At any given time, 4 concurrent epochs have valid keys:
   - **Current epoch** (just started)
   - **Previous epoch** (still widely used)
   - **Legacy epoch -1** (recent messages may still reference)
   - **Legacy epoch -2** (grace period for clock drift)

#### 3.2.2 Lifecycle States

```
┌─────────────────────────────────────────────────────────────────┐
│                    ServiceBundle Lifecycle                       │
└─────────────────────────────────────────────────────────────────┘

  Epoch N-1         Epoch N          Epoch N+1        Epoch N+2
  (Legacy)        (Previous)        (Current)         (Next)
     │                │                 │                │
     │                │                 │                │
     ├─ VALID ────────┼─ VALID ─────────┼─ VALID ────────┤
     │                │                 │                │
     │                │            ▲                     │
     │                │            │                     │
     │                │      [ServiceBundle              │
     │                │       Generated Here]            │
     │                │            │                     │
     │                │            │                     │
     ▼                ▼            ▼                     ▼
  EXPIRED         ACTIVE        ACTIVE              FUTURE
  (pruned after  (widely used) (newly              (pre-generated
   grace period)                distributed)         for next epoch)
```

**Bundle States:**

1. **FUTURE** - Pre-generated bundles for next epoch (5 minutes before boundary)
2. **CURRENT** - Active bundle for the current epoch
3. **ACTIVE** - Previous epoch bundles still in widespread use
4. **LEGACY** - Old epoch bundles kept for message validation
5. **EXPIRED** - Bundles past their validity window (pruned after grace period)

#### 3.2.3 Periodic Bundle Regeneration

The Metadata service regenerates bundles on epoch boundaries:

```
Project: svc-metadata
Package: acl
Class:   ServicesACLWatcherVert.java

private void startEpochAlignedKeyRefresh() {
  LOGGER.info("Starting epoch-aligned key refresh scheduler");
  
  // Calculate time until next epoch boundary
  Instant now = Instant.now();
  long currentEpoch = KeyEpochUtil.epochNumberForInstant(now);
  Instant nextEpochStart = KeyEpochUtil.epochStart(currentEpoch + 1);
  
  // Schedule first refresh 5 minutes BEFORE next epoch (preparation window)
  long delayToNextEpoch = nextEpochStart.toEpochMilli() 
                          - now.toEpochMilli() 
                          - (5 * 60 * 1000); // 5 min early
  
  if (delayToNextEpoch < 0) {
    // We're already past the preparation time, schedule for next epoch
    nextEpochStart = KeyEpochUtil.epochStart(currentEpoch + 2);
    delayToNextEpoch = nextEpochStart.toEpochMilli() - now.toEpochMilli() - (5 * 60 * 1000);
  }
  
  LOGGER.info("First key refresh scheduled in {} ms (at {})", 
              delayToNextEpoch, 
              Instant.ofEpochMilli(now.toEpochMilli() + delayToNextEpoch));
  
  // Set timer for first refresh
  vertx.setTimer(delayToNextEpoch, id -> {
    performKeyRefresh();
    
    // Schedule periodic refresh every epoch (15 minutes)
    periodicTimerId = vertx.setPeriodic(
      KeyEpochUtil.EPOCH_DURATION_MILLIS, 
      periodicId -> performKeyRefresh()
    );
    
    LOGGER.info("Scheduled periodic key refresh every {} ms", 
                KeyEpochUtil.EPOCH_DURATION_MILLIS);
  });
}

private void performKeyRefresh() {
  LOGGER.info("Performing epoch-aligned key refresh for all services");
  
  workerExecutor.executeBlocking(() -> {
    // 1. Generate new topic encryption keys for next epoch
    topicKeyStore.rotateAllTopicKeys();
    
    // 2. Generate new Dilithium signing keys for next epoch
    dilithiumKeyStore.rotateAllServiceKeys();
    
    // 3. Regenerate ServiceBundles with new keys
    if (currentMatrix != null) {
      generateAndDistributeBundles(currentMatrix);
    }
    
    LOGGER.info("Key refresh completed for all services");
    return "SUCCESS";
  });
}
```

**Refresh Process:**

1. **T - 5 minutes**: Pre-generate keys for epoch N+1
2. **T (epoch boundary)**: 
   - New bundles become "current"
   - Previous bundles move to "active"
   - Publish bundle updates via NATS
3. **T + 5 minutes**: Services should have received new bundles
4. **T + 1 hour**: Epoch N-3 keys expire, pruned from bundles

#### 3.2.4 Client-Side Epoch Synchronization

Services synchronize with epoch boundaries using periodic key exchange. The client side
verticle which manages the entire key exchange process for every service is the
KeyExchangeVert. This class manages both the periodic request generation as
well as the response received.

```
Project: svc-core
Package: core.verticle
Class:   KeyExchangeVert.java
private void schedulePeriodicKeyExchange() {
  long currentEpoch = KeyEpochUtil.epochNumberForInstant(Instant.now());
  Instant nextStart = KeyEpochUtil.epochStart(currentEpoch + 1);
  long gracePeriod = 300000L; // 5 minutes after epoch start
  long delay = nextStart.toEpochMilli() - Instant.now().toEpochMilli() + gracePeriod;

  vertx.setTimer(delay, id -> {
    periodicKeyExchangeTimer = vertx.setPeriodic(
      KeyEpochUtil.EPOCH_DURATION_MILLIS, 
      tid -> performKeyExchange()  // Request new ServiceBundle
    );
    performKeyExchange();
  });
}
```

**Why 5-Minute Offsets?**

- **Metadata Service**: Generates bundles 5 minutes *before* epoch boundary
  - Ensures bundles are ready when epoch starts
  - Allows time for distribution via NATS
  
- **Client Services**: Request bundles 5 minutes *after* epoch boundary
  - Gives metadata service time to generate and publish
  - Avoids thundering herd (services stagger requests)

#### 3.2.5 Bundle Versioning

Each ServiceBundle carries version metadata for lifecycle tracking:

```java
ServiceBundle bundle = new ServiceBundle(
  serviceId,
  String.valueOf(Instant.now().toEpochMilli()),  // version = timestamp
  KeyEpochUtil.epochNumberForInstant(Instant.now()),  // keyEpoch
  "key-rotation",  // updateType: "initial", "key-rotation", "acl-update"
  Instant.now(),   // createdAt
  "current"        // status: "current", "active", "legacy", "expired"
);
```

**Update Types:**
- `initial` - First bundle for a new service
- `key-rotation` - Periodic epoch-based rotation
- `acl-update` - Permissions changed in ConfigMap
- `emergency` - Forced rotation due to compromise

---

### 3.3 Encryption Key Model

SecureTransport uses a **hybrid cryptographic model** combining post-quantum and classical algorithms for different purposes:

The encryption keys are associated with a Topic / Subject and not a particular service or Service Pair. This simplifies key management
and allows greater messaging flexibility. As an example if a key was associated with a Service Pair, or a Target Service,
then a message could only be sent to one service at a time. The topic key model allows greater flexibility for
broadcast and multiple receiver messages.

#### 3.3.1 Key Hierarchy

```
┌────────────────────────────────────────────────────────────┐
│                   Cryptographic Key Hierarchy               │
└────────────────────────────────────────────────────────────┘

Level 1: Transport Security (NATS mTLS)
  └─ X.509 Leaf Certificates (RSA-2048)
     └─ Rotated every 6 hours via Cert-Manager
     
Level 2: Key Exchange (Kyber KEM)
  └─ Ephemeral Kyber-1024 Keypairs
     └─ Generated per exchange, discarded after use
     └─ Encapsulates shared secrets for ServiceBundle delivery
     
Level 3: Message Authentication (Dilithium)
  └─ Service Signing Keys (Dilithium5)
     └─ Private key: Signs outgoing messages
     └─ Public key: Distributed in ServiceBundles for verification
     └─ Rotated every epoch (15 minutes)
     
Level 4: Topic Encryption (AES-256-GCM + HKDF)
  └─ Topic-Specific Keys (256-bit AES)
     └─ One key per (topic, epoch) tuple
     └─ Derived keys per message using HKDF
     └─ Rotated every epoch (15 minutes)
```

#### 3.3.2 Topic Encryption Keys (AES-256-GCM)

Topic keys are the workhorses of the system—they encrypt message payloads:

```
Project: svc-core
Package: core.model.service
Class:   TopicKey.java

public class TopicKey {
  private final String keyId;        // "auth.request-epoch-98765"
  private final String topicName;    // "auth.request"
  private final long epochNumber;    // 98765
  private final String algorithm;    // "AES-256-GCM"
  private final byte[] keyData;      // 32-byte random key material
  private final Instant createdTime; // Epoch start time
  private final Instant expiryTime;  // Epoch start + KEY_VALIDITY_MILLIS
  private final String role;         // "current", "next", "legacy"
  
  public TopicKey(String keyId, String topicName, long epochNumber, 
                  String algorithm, byte[] keyData, 
                  Instant createdTime, Instant expiryTime, String role) {
    this.keyId = keyId;
    this.topicName = topicName;
    this.epochNumber = epochNumber;
    this.algorithm = algorithm;
    this.keyData = keyData;  // NEVER exposed outside KeyCache
    this.createdTime = createdTime;
    this.expiryTime = expiryTime;
    this.role = role;
  }
}
```

**Generation Process:**

```
Project: svc-metadata
Package: service
Class:   TopicKeyGenerator.java 

public class TopicKeyGenerator {
  private static final int AES_KEY_LENGTH = 32; // 256-bit
  private final SecureRandom secureRandom = new SecureRandom();

  public TopicKey createTopicKeyForEpoch(String topicName, long epochNumber) {
    Instant validFrom = KeyEpochUtil.epochStart(epochNumber);
    Instant expiry = KeyEpochUtil.epochExpiry(epochNumber);
    
    String keyId = String.format("%s-epoch-%d", topicName, epochNumber);
    
    // Generate cryptographically-secure random key material
    byte[] keyData = new byte[AES_KEY_LENGTH];
    secureRandom.nextBytes(keyData);
    
    LOGGER.debug("Generated topic key for topic {}, epoch {}, valid {} to {}", 
                 topicName, epochNumber, validFrom, expiry);
    
    return new TopicKey(keyId, topicName, epochNumber, 
                        TopicKey.AES_ALGORITHM, keyData, 
                        validFrom, expiry, null);
  }
}
```

**Key Properties:**

- **256-bit entropy**: Generated using `SecureRandom` (NIST SP 800-90A DRBG)
- **Epoch-scoped**: Unique key per (topic, epoch) combination
- **No reuse**: New random key for every epoch rotation
- **Overlapping validity**: Multiple epochs' keys valid simultaneously

#### 3.3.3 HKDF Per-Message Key Derivation

Topic keys aren't used directly—they're used as **key derivation material** with HKDF:

```
Project: svc-core
Package: core.crypto
Class:   AesGcmHkdfCrypto.java

public EncryptedData encrypt(byte[] plaintext, byte[] topicKey, byte[] aad) {
  // 1. Generate random salt (32 bytes)
  byte[] salt = new byte[32];
  secureRandom.nextBytes(salt);
  
  // 2. Derive message-specific key using HKDF
  //    Input Key Material (IKM) = topicKey
  //    Salt = random per-message
  //    Info = Additional Authenticated Data (message metadata)
  HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
  hkdf.init(new HKDFParameters(topicKey, salt, aad));
  
  byte[] derivedKey = new byte[32];
  hkdf.generateBytes(derivedKey, 0, 32);
  
  // 3. Encrypt with AES-256-GCM using derived key
  GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
  // ... GCM encryption with 12-byte IV and 128-bit tag ...
  
  return new EncryptedData(salt, iv, ciphertext, tag);
}
```

Note the EncryptedData class which is returned. Its purpose is to hold the single use hkdf
values.

```
Project: svc-core
Package: core.crypto
Class:   EncryptedData.java

/**
 * Container for all components of an AEAD-encrypted message using HKDF-derived keys.
 * salt - for HKDF key derivation (transmitted with ciphertext)
 * iv   - for AES-GCM (transmitted with ciphertext)
 * ciphertext - the encrypted message
 * tag  - authentication tag from AES-GCM
 */
public final class EncryptedData
{
  private final byte[] salt;
  private final byte[] iv;
  private final byte[] ciphertext;
  private final byte[] tag;

  public EncryptedData( byte[] salt, byte[] iv, byte[] ciphertext, byte[] tag )
  {
    if( salt == null || iv == null || ciphertext == null || tag == null )
    {
      throw new IllegalArgumentException("EncryptedData -All attributes must be provided");
    }
    
    this.salt       = salt.clone();
    this.iv         = iv.clone();
    this.ciphertext = ciphertext.clone();
    this.tag        = tag.clone();
  }

  public byte[] getSalt() { return salt; }
  public byte[] getIv()   { return iv;   }
  public byte[] getCiphertext() { return ciphertext; }
  public byte[] getTag() {  return tag;  }

  /**
   * Serialize all components into a single byte array for transmission
   * Format: [salt_length][salt][iv_length][iv][tag_length][tag][ciphertext]
   */
  public byte[] serialize()
  {
    ByteBuffer buffer = ByteBuffer.allocate( 4 + salt.length + 
                                             4 + iv.length + 
                                             4 + tag.length + 
                                             ciphertext.length 
                                           );

    buffer.putInt( salt.length );
    buffer.put(    salt        );
    buffer.putInt( iv.length   );
    buffer.put(    iv          );
    buffer.putInt( tag.length  );
    buffer.put(    tag         );
    buffer.put(    ciphertext  );

    return buffer.array();
  }

  /**
   * Deserialize byte array back into EncryptedData
   */
  public static EncryptedData deserialize( byte[] data )
  {
    ByteBuffer buffer = ByteBuffer.wrap( data );

    int    saltLength = buffer.getInt();
    byte[] salt       = new byte[saltLength];
    buffer.get( salt );

    int    ivLength = buffer.getInt();
    byte[] iv       = new byte[ivLength];
    buffer.get( iv );

    int    tagLength = buffer.getInt();
    byte[] tag       = new byte[tagLength];
    buffer.get( tag );

    byte[] ciphertext = new byte[buffer.remaining()];
    buffer.get( ciphertext );

    return new EncryptedData( salt, iv, ciphertext, tag );
  }
}
```

**Why HKDF?**

1. **Per-Message Keys**: Each message encrypted with unique derived key
2. **Forward Secrecy**: Compromise of one message doesn't compromise others
3. **Context Binding**: AAD ensures ciphertext tied to message metadata
4. **Key Separation**: Topic key never directly used for encryption

**AAD (Additional Authenticated Data) includes:**
```java
byte[] aad = buildAAD(
  topicName,      // Which topic
  messageId,      // Unique message identifier
  producerId,     // Who created it
  epochNumber,    // When it was created
  timestamp       // Wall-clock time
);
```

#### 3.3.4 Dilithium Signing Keys (Post-Quantum Signatures)

Each service has Dilithium keypairs for signing messages:

```
Project: svc-core
Package: core.model
Class:   DilithiumKey.java 

public class DilithiumKey {
  private final String keyId;           // "authcontroller-sign-epoch-98765"
  private final String serviceId;       // "authcontroller"
  private final PublicKey publicKey;    // Dilithium5 public key (2,592 bytes)
  private final PrivateKey privateKey;  // Dilithium5 private key (4,864 bytes) - null for verify-only keys
  private final long epochNumber;       // 98765
  private final Instant createTime;     // Epoch start
  private final Instant expiryTime;     // Epoch start + KEY_VALIDITY_MILLIS

  // Constructor for full keypair (signing keys - private kept by owner)
  public DilithiumKey(String keyId, String serviceId, KeyPair keyPair, 
                      long epochNumber, Instant createTime, Instant expiryTime) {
    this.keyId = keyId;
    this.serviceId = serviceId;
    this.publicKey = keyPair.getPublic();
    this.privateKey = keyPair.getPrivate();  // Only owner has this
    this.epochNumber = epochNumber;
    this.createTime = createTime;
    this.expiryTime = expiryTime;
  }

  // Constructor for public-only key (verification keys - distributed to consumers)
  public DilithiumKey(String keyId, String serviceId, PublicKey publicKey, 
                      long epochNumber, Instant createTime, Instant expiryTime) {
    this.keyId = keyId;
    this.serviceId = serviceId;
    this.publicKey = publicKey;
    this.privateKey = null;  // Verification-only
    this.epochNumber = epochNumber;
    this.createTime = createTime;
    this.expiryTime = expiryTime;
  }
}
```

**Generation (Rotation tied to KeyEpochUtil):**

```
Project: svc-core
Package: core.service
Class:   DilithiumKeyGenerator.java 

public DilithiumKey createSigningKeyForEpoch(String serviceId, long epochNumber) {
  // Generate Dilithium5 keypair using BouncyCastle PQC
  DilithiumKeyPairGenerator generator = new DilithiumKeyPairGenerator();
  generator.init(new DilithiumKeyGenerationParameters(
    new SecureRandom(), 
    DilithiumParameters.dilithium5  // Highest security level
  ));
  
  AsymmetricCipherKeyPair kp = generator.generateKeyPair();
  DilithiumPublicKeyParameters pub = (DilithiumPublicKeyParameters) kp.getPublic();
  DilithiumPrivateKeyParameters priv = (DilithiumPrivateKeyParameters) kp.getPrivate();
  
  KeyPair keyPair = new KeyPair(
    new DilithiumPublicKey(pub), 
    new DilithiumPrivateKey(priv)
  );
  
  Instant validFrom = KeyEpochUtil.epochStart(epochNumber);
  Instant expiry = KeyEpochUtil.epochExpiry(epochNumber);
  
  return new DilithiumKey(keyId, serviceId, keyPair, epochNumber, validFrom, expiry);
}
```

**Critical Point: Unified Epoch Rotation**

Both topic encryption keys AND Dilithium signing keys rotate together on the same epoch boundaries:

```
Project: svc-metadata
Package: verticle
Class:   ServicesACLWatcherVert.java

private void performKeyRefresh() {
  LOGGER.info("Performing epoch-aligned key refresh for all services");
  
  workerExecutor.executeBlocking(() -> {
    // Current epoch drives BOTH key types
    long currentEpoch = KeyEpochUtil.epochNumberForInstant(Instant.now());
    
    // 1. Generate new topic encryption keys for current, next, and legacy epochs
    for (String topic : allTopics) {
      topicKeyStore.getAllValidKeysForTopic(topic);  // Generates epoch-based keys
    }
    
    // 2. Generate new Dilithium signing keys for SAME epochs
    for (String serviceId : allServices) {
      dilithiumKeyStore.getAllValidKeysForService(serviceId);  // Generates epoch-based keys
    }
    
    // 3. Regenerate ServiceBundles with BOTH key types aligned to same epoch
    generateAndDistributeBundles(currentMatrix);
    
    LOGGER.info("Key refresh completed - topic keys and signing keys synchronized to epoch {}", 
                currentEpoch);
  });
}
```

**This includes the Metadata service's own signing keys**—they rotate on the same 15-minute epoch boundaries as all other services:

```
// Metadata service generates its own signing keys
DilithiumKey metadataSigningKey = 
  dilithiumKeyGenerator.createSigningKeyForEpoch("metadata", currentEpoch);

// Stored in Metadata's own ServiceBundle
ServiceBundle metadataBundle = bundleManager.generateServiceBundleOnDemand(
  "metadata", 
  "key-rotation", 
  currentMatrix
);

// metadataBundle.signingKeys contains Dilithium keys at epochs N-1, N, N+1
// All services that consume from Metadata receive its public keys in their verifyKeys map
```

**Distribution Model:**

The Dilithium Key Pair is generated for each service by the Service Bundle processing. Based upon the Service permissions
and the particular Service for a Service Bundle, the Signing key for the service included, and all necessary
verification keys are included within each service bundle. 

#### 3.3.5 Key Size Comparison

**Post-Quantum Overhead:**

| Key Type | Classical Size | PQC Size | Ratio |
|----------|---------------|----------|-------|
| **Public Key** | RSA-2048: 294 bytes | Dilithium5: 2,592 bytes | 8.8× |
| **Signature** | ECDSA P-256: 64 bytes | Dilithium5: 4,595 bytes | 71.8× |
| **KEM Public Key** | ECDH P-256: 65 bytes | Kyber-1024: 1,568 bytes | 24.1× |
| **Topic Encryption** | AES-256: 32 bytes | AES-256: 32 bytes | 1.0× |

**Mitigation Strategies:**

1. **Avro Binary Serialization**: Compact encoding (no JSON overhead)
2. **Caffeine Caching**: Avoid repeated deserialization of large keys
3. **Epoch-Based Pruning**: Only keep 4 epochs of keys (1-hour window)
4. **Lazy Loading**: Fetch verification keys on-demand when needed

#### 3.3.6 Key Rotation Summary

| Key Type | Rotation Frequency | Validity Window | Storage Location |
|----------|-------------------|-----------------|------------------|
| **NATS Leaf Certs** | 6 hours (Cert-Manager) | 6 hours | Kubernetes Secrets |
| **Kyber Keypairs** | Per exchange (ephemeral) | Single use | In-memory only |
| **Dilithium Signing Keys** | 15 minutes (epoch) | 1 hour | ServiceBundle + OpenBao |
| **Topic Encryption Keys** | 15 minutes (epoch) | 1 hour | ServiceBundle + OpenBao |

**Cascading Rotation Timeline:**

```
T=00:00  Epoch 100 starts
         ├─ Generate topic keys for epoch 100
         ├─ Generate Dilithium keys for epoch 100
         └─ Distribute ServiceBundles with new keys

T=00:15  Epoch 101 starts
         ├─ Epoch 100 keys still valid (until T=01:00)
         ├─ Epoch 99 keys still valid (until T=00:45)
         └─ Services use newest keys, fall back to older if needed

T=01:00  Epoch 104 starts
         ├─ Epoch 100 keys expire
         └─ Prune epoch 100 keys from ServiceBundles
```

---

### 3.4 Bundle Generation Process

The `ServiceBundleManager` generates bundles based on the ACL matrix:

```
Project: xvc-metadata
Package: acl
Class:   ServiceBundleManager.java

public Future<ServiceBundle> generateServiceBundleOnDemand(
    String serviceId, 
    String updateType, 
    ServicesACLMatrix matrix) {
  
  return workerExecutor.executeBlocking(() -> {
    Instant now = Instant.now();
    long keyEpoch = KeyEpochUtil.epochNumberForInstant(now);
    
    // 1. Build Topic Permissions + Keys
    Map<String, TopicPermission> topicPermissions = new HashMap<>();
    Map<String, Map<String, TopicKey>> topicKeys = new HashMap<>();
    
    Set<String> authorizedTopics = matrix.getTopicsForService(serviceId);
    
    for (String topicFqn : authorizedTopics) {
      Set<String> access = matrix.getServiceTopicAccess(serviceId, topicFqn);
      boolean canProduce = access.contains("produce");
      boolean canConsume = access.contains("consume");
      
      // Get ALL valid keys for this topic (current + overlapping epochs)
      Map<String, TopicKey> keyMap = topicKeyStore.getAllValidKeysForTopic(topicFqn);
      
      // AUTHORIZATION ENFORCEMENT: Only include keys if service is authorized
      topicPermissions.put(topicFqn, 
        new TopicPermission(serviceId, topicFqn, canProduce, canConsume, keyMap));
      
      if (keyMap != null && !keyMap.isEmpty()) {
        topicKeys.put(topicFqn, keyMap);
      }
    }
    
    // 2. Get Signing Keys (Dilithium) for THIS service
    Map<Long, DilithiumKey> signingKeys = 
        dilithiumKeyStore.getAllValidKeysForService(serviceId);
    
    // 3. Get Verify Keys for ALL services this service can consume from
    Map<String, Map<Long, DilithiumKey>> verifyKeys = new HashMap<>();
    Set<String> consumeFromServices = new HashSet<>();
    
    for (String topic : authorizedTopics) {
      if (matrix.getServiceTopicAccess(serviceId, topic).contains("consume")) {
        // Find all services that can PRODUCE to this topic
        Set<String> producers = matrix.getServicesForTopic(topic);
        for (String producerService : producers) {
          if (matrix.getServiceTopicAccess(producerService, topic).contains("produce")) {
            consumeFromServices.add(producerService);
          }
        }
      }
    }
    
    // Get public verification keys for all producers
    for (String producerService : consumeFromServices) {
      Map<Long, DilithiumKey> pubKeys = 
          dilithiumKeyStore.getAllValidKeysForService(producerService);
      verifyKeys.put(producerService, pubKeys);
    }
    
    // 4. Construct immutable ServiceBundle
    return new ServiceBundle(
        serviceId, version, keyEpoch, updateType, now, "current",
        signingKeys, verifyKeys, topicKeys, topicPermissions
    );
  });
}
```

The ServicesACLWatcherVert is responsible for managing the generation of the
Service Bundles for every authorized service. After a bundle is created it is also
stored within OpenBao for (future) bootstrap and emergency access by the service if for some reason the 
service finds it does not have the particular epoch service bundle.

The ServicesACLWatcherVert also maintains a periodic timer associated with the epoch
boundaries for regenerating new Service bundles for all services.
 
```
Project: xvc-metadata
Package: acl
Class:   ServiceACLWatcherVert.java

  /**
   * Generate and distribute ServiceBundles for all services in the matrix.
   * Now also stores bundles in OpenBao for bootstrap capability.
   */
  private void generateAndDistributeBundles( ServicesACLMatrix matrix )
  {
    try
    {
      LOGGER.info( "Generating ServiceBundles for all services in matrix" );
      for( String serviceId : matrix.getAllServices() )
      {
        bundleManager.generateServiceBundleOnDemand( serviceId, "update", matrix )
         .onSuccess( bundle -> 
          {
            LOGGER.info( "Generated ServiceBundle for service {}", serviceId );
            
            // Store bundle in OpenBao for bootstrap capability
            storeBundleInVault( serviceId, bundle.getKeyEpoch(), bundle )
              .onSuccess( v -> LOGGER.info( "Stored ServiceBundle in OpenBao for service {}", serviceId ))
              .onFailure( e -> LOGGER.error( "Failed to store ServiceBundle in OpenBao for service {}: {}", 
                                            serviceId, e.getMessage(), e ));
          })
         .onFailure( e -> 
          {
            LOGGER.error( "Failed to generate ServiceBundle for service: " + serviceId, e );
          });
      }
    } 
    catch( Exception e )
    {
      LOGGER.error( "Failed to generate or distribute ServiceBundles", e );
    }
  }
```
 
### 3.3 Critical Authorization Logic

**The Enforcement Happens at Bundle Generation Time:**

```java
// AuthController requests bundle for service "authcontroller"
// ACL Matrix shows:
//   - Can CONSUME from "auth.auth-request"
//   - Can PRODUCE to "gatekeeper.responder"

// Result: ServiceBundle contains:
topicPermissions = {
  "auth.auth-request": TopicPermission(
    canConsume: true,
    canProduce: false,
    topicKeys: { "auth.request-epoch-12345" -> TopicKey(...) }  // INCLUDED
  ),
  "gatekeeper.responder": TopicPermission(
    canConsume: false,
    canProduce: true,
    topicKeys: { "gatekeeper.responder-epoch-12345" -> TopicKey(...) }  // INCLUDED
  )
}

// ServiceBundle does NOT contain keys for unauthorized topics
// If authcontroller tries to subscribe to "metadata.internal", it fails:
//   - No topic key in bundle = cannot decrypt messages
//   - Mathematically impossible, not just policy-blocked
```

### 3.4 TopicPermission Structure

```
Project: svc-core
Package: core.model.service
Class:   TopicPermission

public class TopicPermission {
  private final String serviceId;
  private final String topicName;
  private final boolean producePermission;  // Can this service publish?
  private final boolean consumePermission;  // Can this service subscribe?
  
  // The actual encryption keys (only present if authorized)
  private final Map<String, TopicKey> topicKeys;  // keyId -> TopicKey
  
  public TopicPermission(String serviceId, String topicName, 
                         boolean produce, boolean consume,
                         Map<String, TopicKey> keys) {
    this.serviceId = serviceId;
    this.topicName = topicName;
    this.producePermission = produce;
    this.consumePermission = consume;
    this.topicKeys = keys != null ? keys : new HashMap<>();
  }
}
```

**Why This Matters:**
- Permission flags (`producePermission`, `consumePermission`) are **metadata** for logging/auditing
- **Actual enforcement** comes from key possession—if you don't have the `TopicKey`, you can't decrypt the message
- Revocation is automatic: don't include the service in the next epoch's bundle

---

## 4. Key Exchange Protocol: Secure Delivery with Kyber

### 4.1 The Key Exchange Challenge

**Problem:** How do you securely deliver a ServiceBundle to a service over an untrusted network?

**Requirements:**
- Post-quantum secure (resistant to quantum computer attacks)
- Forward secrecy (compromise of long-term keys doesn't compromise past sessions)
- Mutual authentication (both parties verify each other's identity)
- Protection against replay attacks

**Solution:** Kyber Key Encapsulation Mechanism (KEM) + Dilithium signatures

### 4.2 Key Exchange Flow

```
┌─────────────┐                                    ┌──────────────┐
│ AuthController│                                  │   Metadata   │
│   (Client)    │                                  │   Service    │
└───────┬───────┘                                  └──────┬───────┘
        │                                                 │
        │  1. Generate Kyber keypair (ephemeral)          │
        │     publicKey, privateKey = KyberKEM.keygen()   │
        │                                                 │
        │  2. Create KyberExchangeMessage                 │
        │     - sourceServiceId: "authcontroller"         │
        │     - publicKey: [kyber public key bytes]       │
        │     - secretKeyId: UUID                         │
        │                                                 │
        │  3. Publish to "metadata.bundle-pull.svc-metadata"
        ├────────────────────────────────────────────────>│
        │                                                 │
        │                                                 │  4. Receive request
        │                                                 │     via pull consumer
        │                                                 │
        │                                                 │  5. Extract client's
        │                                                 │     Kyber public key
        │                                                 │
        │                                                 │  6. Encapsulate:
        │                                                 │     sharedSecret, ciphertext
        │                                                 │       = encapsulate(publicKey)
        │                                                 │
        │                                                 │  7. Get ServiceBundle for
        │                                                 │     "authcontroller"
        │                                                 │
        │                                                 │  8. Encrypt bundle:
        │                                                 │     encrypted = AES-GCM-HKDF
        │                                                 │       .encrypt(bundle, sharedSecret)
        │                                                 │
        │                                                 │  9. Create SignedMessage:
        │                                                 │     - payload: encrypted
        │                                                 │     - signature: Dilithium
        │                                                 │
        │                                                 │  10. Publish response to
        │  11. Receive response via pull consumer         │      "metadata.bundle-pull.svc-authcontroller"
        │<────────────────────────────────────────────────┤
        │                                                 │
        │  12. Decapsulate:                               │
        │      sharedSecret = decapsulate(                │
        │        ciphertext, privateKey)                  │
        │                                                 │
        │  13. Verify Dilithium signature                 │
        │                                                 │
        │  14. Decrypt ServiceBundle:                     │
        │      bundle = AES-GCM-HKDF                      │
        │        .decrypt(encrypted, sharedSecret)        │
        │                                                 │
        │  15. Load keys into KeyCache                    │
        │                                                 │
```

### 4.3 Client-Side: Initiating Key Exchange

```
Project: svc-core
Package: core.verticle
Class:   KeyExchangeVert.java

public class KeyExchangeVert extends AbstractVerticle {
  
  private final String serviceId;
  private final NatsTLSClient natsClient;
  private final KeySecretManager keyCache;
  
  /**
   * Initiate Kyber key exchange to request ServiceBundle
   */
  public Future<Void> initiateKeyExchange() {
    return workerExecutor.executeBlocking(() -> {
      
      // 1. Generate ephemeral Kyber keypair
      KyberKEMCrypto kyber = new KyberKEMCrypto();
      KeyPair kyberKeyPair = kyber.generateKyberKeyPair();
      
      String secretKeyId = UUID.randomUUID().toString();
      
      // 2. Store private key for later decapsulation
      keyCache.putKyberKeyPair(secretKeyId, kyberKeyPair);
      
      // 3. Create exchange message with public key
      KyberExchangeMessage request = new KyberExchangeMessage(
          serviceId,                         // Who is requesting
          "metadata",                         // Who to send to
          kyberKeyPair.getPublic().getEncoded(),  // Kyber public key
          null,                              // No encapsulation yet
          secretKeyId,
          null,                              // No bundle yet
          Instant.now()
      );
      
      // 4. Publish to metadata service's pull consumer subject
      String requestSubject = ServiceCoreIF.KeyExchangeStreamBase + "metadata";
      byte[] msgBytes = KyberExchangeMessage.serialize(request);
      
      natsClient.publish(requestSubject, msgBytes);
      
      LOGGER.info("Published Kyber exchange request to {}", requestSubject);
      return null;
    });
  }
}
```

### 4.4 Server-Side: Processing Key Exchange Request

```
Project: svc-metadata
Package: verticle
Class:   MetadataKeyExchangeVert.java

protected Future<Void> processKeyExchRequestAsync(KyberExchangeMessage request) {
  
  return workerExecutor.executeBlocking(() -> {
    
    // 1. Extract client's Kyber public key
    byte[] clientPublicKeyBytes = request.getPublicKey();
    KyberKEMCrypto kyber = new KyberKEMCrypto();
    
    // 2. Encapsulate: generates shared secret + ciphertext
    Map<String, byte[]> encapResult = kyber.encapsulate(clientPublicKeyBytes);
    byte[] sharedSecret = encapResult.get("sharedSecret");
    byte[] ciphertext = encapResult.get("ciphertext");
    
    // 3. Store shared secret for later reference
    SharedSecretInfo secretInfo = new SharedSecretInfo(
        request.getSecretKeyId(),
        sharedSecret,
        Instant.now(),
        Instant.now().plusSeconds(300)  // 5-minute validity
    );
    keyCache.putEncyptionSharedSecret(secretInfo);
    
    return new Object[] { sharedSecret, ciphertext };
    
  }).compose(result -> {
    byte[] sharedSecret = (byte[]) ((Object[]) result)[0];
    byte[] ciphertext = (byte[]) ((Object[]) result)[1];
    
    // 4. Get ServiceBundle for requesting service
    return getCurrentServiceBundle(request.getSourceSvcId())
      .compose(bundle -> {
        
        // 5. Serialize bundle
        return workerExecutor.executeBlocking(() -> 
            ServiceBundle.serialize(bundle));
        
      }).compose(serializedBundle -> {
        
        // 6. Create SignedMessage with encrypted bundle
        SharedSecretInfo secretInfo = new SharedSecretInfo(
            request.getSecretKeyId(), sharedSecret, 
            Instant.now(), Instant.now().plusSeconds(300));
        
        return signedMessageProcessor.createSignedMessage(
            request.getSourceSvcId(),
            serializedBundle,
            "ServiceBundle",
            "ServiceBundle",
            ServiceCoreIF.KeyExchangeStreamBase + request.getSourceSvcId(),
            secretInfo.getSharedSecret()  // Encrypt with shared secret
        );
        
      }).compose(signedMsg -> {
        
        // 7. Create response message with encapsulation + signed bundle
        KyberExchangeMessage response = new KyberExchangeMessage(
            serviceId,                     // From metadata
            request.getSourceSvcId(),      // To requesting service
            null,                          // No public key in response
            ciphertext,                    // Kyber encapsulation
            request.getSecretKeyId(),
            SignedMessage.serialize(signedMsg),  // Encrypted ServiceBundle
            Instant.now()
        );
        
        // 8. Publish response to service-specific subject
        String responseSubject = ServiceCoreIF.KeyExchangeStreamBase + 
                                 request.getSourceSvcId();
        
        return natsClient.publishAsync(
            responseSubject, 
            KyberExchangeMessage.serialize(response));
      });
  });
}
```

### 4.5 Client-Side: Processing Key Exchange Response

```
Project: svc-core
Package: core.verticle
Class:   KeyExchangeVert.java 

protected Future<Void> processKeyExchResponseAsync(KyberExchangeMessage response) {
  
  return workerExecutor.executeBlocking(() -> {
    
    // 1. Retrieve our private key
    PrivateKey myKyberPrivateKey = keyCache.getKyberPrivateKey(
        response.getSecretKeyId());
    
    if (myKyberPrivateKey == null) {
      throw new RuntimeException("Kyber private key not found for: " + 
                                 response.getSecretKeyId());
    }
    
    // 2. Decapsulate to recover shared secret
    KyberKEMCrypto kyber = new KyberKEMCrypto();
    byte[] sharedSecret = kyber.decapsulate(
        response.getEncapsulation(), 
        myKyberPrivateKey);
    
    // 3. Store shared secret
    SharedSecretInfo secretInfo = new SharedSecretInfo(
        response.getSecretKeyId(),
        sharedSecret,
        Instant.now(),
        Instant.now().plusSeconds(300)
    );
    keyCache.putEncyptionSharedSecret(secretInfo);
    
    return sharedSecret;
    
  }).compose(sharedSecret -> {
    
    // 4. Process encrypted ServiceBundle
    if (response.hasAdditionalData()) {
      return processServiceBundle(
          response.getAdditionalData(), 
          sharedSecret, 
          response.getSourceSvcId());
    }
    
    return Future.succeededFuture();
  });
}

private Future<ServiceBundle> processServiceBundle(
    byte[] signedMsgBytes, 
    byte[] sharedSecret, 
    String sourceServiceId) {
  
  return workerExecutor.executeBlocking(() -> {
    
    // 1. Deserialize SignedMessage
    SignedMessage signedMsg = SignedMessage.deSerialize(signedMsgBytes);
    
    // 2. Extract encrypted payload
    EncryptedData encData = EncryptedData.deserialize(signedMsg.getPayload());
    
    // 3. Decrypt using shared secret
    AesGcmHkdfCrypto aes = new AesGcmHkdfCrypto();
    byte[] decryptedBytes = aes.decrypt(encData, sharedSecret);
    
    // 4. Deserialize ServiceBundle
    ServiceBundle bundle = ServiceBundle.deSerialize(decryptedBytes);
    
    return new Object[] { bundle, signedMsg, decryptedBytes };
    
  }).compose(result -> {
    ServiceBundle bundle = (ServiceBundle) ((Object[]) result)[0];
    SignedMessage signedMsg = (SignedMessage) ((Object[]) result)[1];
    byte[] decryptedBytes = (byte[]) ((Object[]) result)[2];
    
    // 5. Verify Dilithium signature
    return verifyAndLoadServiceBundle(
        bundle, signedMsg, decryptedBytes, sourceServiceId);
  });
}

private Future<ServiceBundle> verifyAndLoadServiceBundle(
    ServiceBundle bundle, 
    SignedMessage signedMsg, 
    byte[] bundleBytes,
    String sourceServiceId) {
  
  // Get verification key for metadata service
  Map<Long, DilithiumKey> verifyMap = bundle.getVerifyKeys().get(sourceServiceId);
  long signerKeyId = signedMsg.getSignerKeyId();
  
  if (verifyMap == null || !verifyMap.containsKey(signerKeyId)) {
    return Future.failedFuture(
        "No verification key for " + sourceServiceId + " epoch " + signerKeyId);
  }
  
  DilithiumKey signingKey = verifyMap.get(signerKeyId);
  
  // Verify signature
  return signedMsgProcessor.verifyWithKey(
      bundleBytes, 
      signedMsg.getSignature(), 
      signingKey)
    .compose(verified -> {
      
      if (!verified) {
        return Future.failedFuture("Signature verification failed");
      }
      
      // Load bundle into KeyCache
      keyCache.loadFromServiceBundle(bundle);
      
      LOGGER.info("✅ Successfully loaded ServiceBundle from {}", sourceServiceId);
      return Future.succeededFuture(bundle);
    });
}
```

---

## 5. Security Properties

### 5.1 Post-Quantum Security

**Kyber (ML-KEM):**
- NIST-standardized lattice-based cryptography
- Resistant to Shor's algorithm (quantum factoring/discrete log attacks)
- Encapsulation size: ~1,568 bytes (Kyber1024)

**Dilithium (ML-DSA):**
- NIST-standardized lattice-based signatures
- Resistant to quantum attacks on signature schemes
- Signature size: ~4,595 bytes (Dilithium5)

### 5.2 Forward Secrecy

**Ephemeral Kyber Keypairs:**
```java
// NEW keypair generated for EVERY key exchange
KeyPair kyberKeyPair = kyber.generateKyberKeyPair();
```

**Property:** Past ServiceBundle exchanges cannot be decrypted (the ephemeral Kyber keys are discarded after use).

### 5.3 Replay Attack Protection

**Time-Based Validity:**
```java
SharedSecretInfo secretInfo = new SharedSecretInfo(
    secretKeyId,
    sharedSecret,
    Instant.now(),
    Instant.now().plusSeconds(300)  // 5-minute window
);
```

**Unique Request IDs:**
```java
String secretKeyId = UUID.randomUUID().toString();
```

**Property:** Old key exchange messages cannot be replayed (expired shared secrets are rejected).

### 5.4 Mutual Authentication

**Client authenticates server:**
- ServiceBundle contains metadata service's Dilithium public key
- Client verifies Dilithium signature on encrypted bundle

**Server authenticates client:**
- Client's request comes from authenticated NATS mTLS connection
- Future enhancement: Client could sign key exchange request

---

## 6. Key Rotation Integration

### 6.1 ServiceBundle Updates

When keys rotate (every 15 minutes for topic keys, every epoch for signing keys):

```java
// Triggered by periodic timer or ACL change
Future<Void> rotateKeys() {
  return topicKeyGenerator.rotateAllTopicKeys()
    .compose(v -> dilithiumKeyGenerator.rotateServiceKeys())
    .compose(v -> {
      // Regenerate ALL ServiceBundles with new keys
      return regenerateAllServiceBundles("key-rotation");
    })
    .compose(v -> {
      // Push updated bundles via metadata.bundle-push.svc-* topics
      return publishBundleUpdates();
    });
}
```

### 6.2 Pull vs Push Delivery

**Pull Model (On-Demand):**
- Service initiates key exchange when it starts
- Service requests update when it detects missing keys
- Use case: Initial bootstrap, recovery from errors

**Push Model (Proactive):**
- Metadata service publishes bundle updates on rotation
- Services receive updates via `metadata.bundle-push.svc-{serviceId}` topics
- Use case: Scheduled rotations, ACL changes

**Hybrid Approach:**
```java
// Services subscribe to push updates
vertx.eventBus().consumer("metadata.bundle-push." + serviceId, msg -> {
  ServiceBundle bundle = ServiceBundle.deSerialize(msg.body().getBytes());
  keyCache.loadFromServiceBundle(bundle);
});

// Fallback: Pull if we're missing keys
if (keyCache.getTopicKey(topicName, epoch) == null) {
  keyExchangeVert.initiateKeyExchange();
}
```

---

## 7. Operational Insights

### 7.1 Bundle Size Considerations

**Typical ServiceBundle Sizes:**
- **Minimal service** (2 topics, 1 producer): ~15 KB
- **Gateway service** (10 topics, 5 producers): ~75 KB
- **Metadata service** (all topics): ~200 KB

**PQC Overhead:**
- Dilithium5 public key: 2,592 bytes
- Dilithium5 signature: 4,595 bytes
- Kyber1024 public key: 1,568 bytes

**Mitigation:**
- Avro binary serialization (compact)
- Caffeine caching (avoid repeated deserialization)
- Compression for storage (bundles compress well)

### 7.2 Performance Characteristics

**Key Exchange Latency:**
```
Kyber encapsulation:     ~0.1 ms
Dilithium signing:       ~5 ms
AES-GCM encryption:      ~0.05 ms
Network round-trip:      ~10-50 ms (cluster-local)
Total:                   ~20-60 ms
```

**Bundle Loading:**
```
Deserialization:         ~5 ms
Signature verification:  ~2 ms
Cache population:        ~1 ms
Total:                   ~8 ms
```

### 7.3 Monitoring & Observability

**Key Metrics:**
```java
// Track key exchange success rate
metrics.counter("keyexchange.requests.total");
metrics.counter("keyexchange.requests.success");
metrics.counter("keyexchange.requests.failed");

// Track bundle age
metrics.gauge("servicebundle.age.seconds", () -> 
    Duration.between(currentBundle.getCreatedAt(), Instant.now()).getSeconds());

// Track key cache hit rate
metrics.counter("keycache.lookups.total");
metrics.counter("keycache.lookups.hit");
```

**Critical Alerts:**
- ServiceBundle older than 2x rotation period
- Key exchange failure rate > 1%
- Missing verification keys for active producers
- Shared secret expiration without renewal

---

## 8. Comparison with Traditional Models

| Aspect | Traditional ACL | SecureTransport ServiceBundle |
|--------|----------------|------------------------------|
| **Authorization Check** | Every request queries PDP | One-time at key distribution |
| **Performance** | N requests = N policy lookups | Zero runtime overhead |
| **Scalability** | PDP becomes bottleneck | Distributed enforcement |
| **Failure Mode** | PDP down = outage | Cached keys continue working |
| **Revocation** | Immediate (flush cache) | Next epoch (15-60 min) |
| **Cryptographic Proof** | No | Yes (mathematically enforced) |
| **Zero-Trust** | Requires external enforcement | Built-in (every message) |
| **PQC Ready** | N/A | Yes (Kyber + Dilithium) |

---

## 9. Limitations & Trade-offs

### 9.1 Revocation Latency

**Challenge:** Revocation only takes effect at the next epoch boundary (15-60 minutes).

**Mitigation:**
- Emergency revocation: Force immediate key rotation
- Blacklist compromised keys (checked on message receipt)
- Reduce epoch duration for high-security scenarios

### 9.2 Bundle Size Growth

**Challenge:** Services with many topics/producers get large bundles.

**Mitigation:**
- Lazy loading (request keys on-demand)
- Incremental updates (only changed keys)
- Service segmentation (micro-permissions)

### 9.3 Clock Synchronization

**Challenge:** Epoch boundaries require synchronized clocks.

**Mitigation:**
- NTP/PTP time sync
- Overlapping validity windows (current + next + legacy epochs)
- Automatic epoch calculation with tolerance

---

## 10. Conclusion

The ServiceBundle + Key Exchange architecture demonstrates that **cryptographic authorization** is not just theoretically sound—it's operationally viable for high-throughput microservices.

**Key Innovations:**

1. **Declarative ACL** → Kubernetes ConfigMap simplifies permission management
2. **Authorization = Key Possession** → No runtime policy checks, cryptographically enforced
3. **Post-Quantum Security** → Kyber + Dilithium future-proof the system
4. **Zero-Downtime Updates** → Pull + push hybrid ensures continuous operation
5. **Observability** → Every bundle generation/exchange is logged and metered

**What's Next:**

- **Blog 4**: Automated Certificate Rotation (Intermediate + Leaf) and certificate management
- **Blog 5**: OpenBao Integration and App Role token management
- **Blog 6**: NATS messaging with short-lived keys and topic permissions
- **Blog 7**: Alternative Architectures Tested

---

**Explore the code:**
- [ServiceBundle.java](https://github.com/t-snyder/010-SecureTransport/blob/main/svc-core/src/main/java/core/model/ServiceBundle.java)
- [ServiceBundleManager.java](https://github.com/t-snyder/010-SecureTransport/blob/main/svc-metadata/src/main/java/acl/ServiceBundleManager.java)
- [KeyExchangeVert.java](https://github.com/t-snyder/010-SecureTransport/blob/main/svc-core/src/main/java/core/verticle/KeyExchangeVert.java)
- [ServicesACLMatrix.java](https://github.com/t-snyder/010-SecureTransport/blob/main/svc-metadata/src/main/java/acl/ServicesACLMatrix.java)

---

**License:** Apache 2.0  
**Repository:** https://github.com/t-snyder/010-SecureTransport
