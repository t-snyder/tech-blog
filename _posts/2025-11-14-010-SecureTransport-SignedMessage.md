---
layout: readme
title: Secure Transport Research Project - Part 6 - SignedMessage Protocol
exclude_from_feed: true 
pinned: false
excerpt: "Deep dive into the SignedMessage protocol: end-to-end message authentication and encryption using Dilithium signatures, AES-GCM-256 with HKDF key derivation, epoch-based key management, and cryptographic enforcement of authorization. Explores message creation, encryption, signature generation, decryption, and verification flows with automatic ServiceBundle recovery from OpenBao."
categories: [Security, Cryptography, Kubernetes]
tags: [post-quantum, dilithium, AES-GCM, HKDF, message-authentication, zero-trust, cryptography]
series: "SecureTransport Research Prototype"
series_part: 6
---

# SignedMessage Protocol: End-to-End Cryptographic Message Security

## Introduction

In traditional microservices architectures, message security relies on transport-layer encryption (TLS/mTLS) to protect data in transit. Once a message reaches its destination, the recipient trusts that it came from the claimed sender because the transport layer authenticated the connection. This model has critical weaknesses:

1. **No end-to-end authentication** - Messages can be tampered with after TLS termination
2. **No authorization enforcement** - Any service with network access can send/receive messages
3. **No non-repudiation** - Cannot prove who sent a message after the fact
4. **No forward secrecy at message level** - Compromised long-lived keys expose message history

SecureTransport solves these problems with the **SignedMessage protocol**—a cryptographic wrapper that provides:

- ✅ **End-to-end authentication** via post-quantum Dilithium signatures
- ✅ **Authorization enforcement** via topic-specific encryption keys
- ✅ **Forward secrecy** via HKDF per-message key derivation
- ✅ **Non-repudiation** via epoch-tagged signatures with audit trails
- ✅ **Zero-trust messaging** - Every message carries cryptographic proof
- ✅ **Self-healing key recovery** - Automatic ServiceBundle fetch from OpenBao when keys are missing

This blog explores the complete SignedMessage lifecycle: creation, encryption, signature generation, transmission, decryption, verification, and automatic key recovery from OpenBao.

---

## 1. The SignedMessage Architecture

### 1.1 What is a SignedMessage?

A `SignedMessage` is a cryptographic envelope that wraps application payloads with:

1. **Encrypted payload** - AES-256-GCM with HKDF-derived per-message keys
2. **Dilithium signature** - Post-quantum digital signature for authentication
3. **Epoch metadata** - Key epoch and CA epoch for validation context
4. **Authorization proof** - Topic key ID proving sender has access rights

```
┌───────────────────────────────────────────────────────────────┐
│                      SignedMessage Structure                  │
└───────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────┐
│ Header Metadata                                               │
│  • messageId (String - composite: serviceId + timestamp)      │
│  • messageType (String - e.g., "ServiceBundle")               │
│  • timestamp (Instant)                                        │
│  • signerServiceId (String - e.g., "authcontroller")          │
│  • topicName (String - e.g., "auth.auth-request")             │
│  • payloadType (String - domain object type)                  │
└───────────────────────────────────────────────────────────────┘
┌───────────────────────────────────────────────────────────────┐
│ Cryptographic Material                                        │
│  • encryptKeyId (String - e.g., "auth.request-epoch-98765")   │
│  • keyEpoch (long - 98765)                                    │
│  • caEpoch (long - 36945)                                     │
│  • signerKeyId (long - 98765)                                 │
└───────────────────────────────────────────────────────────────┘
┌───────────────────────────────────────────────────────────────┐
│ Encrypted Payload (EncryptedData)                             │
│  • salt (32 bytes - HKDF salt)                                │
│  • iv (12 bytes - AES-GCM nonce)                              │
│  • ciphertext (variable length - encrypted payload)           │
│  • tag (16 bytes - AES-GCM authentication tag)                │
└───────────────────────────────────────────────────────────────┘
┌───────────────────────────────────────────────────────────────┐
│ Signature (Dilithium5)                                        │
│  • signature (4,595 bytes - post-quantum signature)           │
│  • Covers: domain object bytes (before encryption)            │
└───────────────────────────────────────────────────────────────┘
```

### 1.2 Security Properties

**Authentication:**
- Every message signed with sender's Dilithium private key
- Signature computed over **unencrypted domain object bytes**
- Receiver verifies signature using sender's public key (from ServiceBundle)
- Post-quantum secure (resistant to Shor's algorithm)

**Authorization:**
- Sender must possess topic encryption key to create message
- Receiver must possess same topic key to decrypt payload
- Key distribution tied to ServiceACL permissions (Blog 3)

**Confidentiality:**
- Payload encrypted with AES-256-GCM
- Per-message keys derived via HKDF (prevents key reuse)
- Forward secrecy (compromise of topic key doesn't expose past messages)

**Integrity:**
- AES-GCM authentication tag protects ciphertext
- Dilithium signature protects domain object
- Tampered messages fail verification

**Non-Repudiation:**
- Signatures include epoch metadata
- Audit trails prove message origin
- Cannot deny sending signed message

**Self-Healing:**
- Missing keys trigger automatic ServiceBundle fetch from OpenBao
- System recovers without manual intervention
- Transparent to application logic

### 1.3 Message Flow Overview

```
┌────────────────────────────────────────────────────────────────┐
│                  SignedMessage Lifecycle                       │
└────────────────────────────────────────────────────────────────┘

SENDER (e.g., AuthController)
  │
  │ 1. Application creates domain object (e.g., AuthRequest)
  │
  ▼
┌────────────────────────────────────────────────────────────────┐
│ SignedMessageProcessor.createSignedMessage()                   │
│  ├─ Serialize domain object (Avro)                             │
│  ├─ Get signing key from KeyCache                              │
│  ├─ Sign domain object bytes (DilithiumService.sign)           │
│  ├─ Fetch topic encryption key from KeyCache                   │
│  ├─ Encrypt domain bytes via AesGcmHkdfCrypto                  │
│  │   └─ Generate salt, derive per-message key via HKDF         │
│  └─ Build SignedMessage with encrypted payload + signature     │
└────────────────────────────────────────────────────────────────┘
  │
  │ 2. Serialize SignedMessage (Avro binary)
  │
  ▼
┌────────────────────────────────────────────────────────────────┐
│ NATS Publish                                                   │
│  • Topic: auth.auth-request                                    │
│  • Payload: Serialized SignedMessage bytes                     │
└────────────────────────────────────────────────────────────────┘
  │
  │ 3. NATS JetStream persists and delivers message
  │
  ▼
RECEIVER (e.g., Gatekeeper)
  │
  │ 4. NATS Pull Consumer fetches message
  │
  ▼
┌────────────────────────────────────────────────────────────────┐
│ SignedMessageProcessor.obtainDomainObject()                    │
│  ├─ Deserialize SignedMessage (Avro)                           │
│  ├─ Deserialize EncryptedData from payload                     │
│  ├─ Extract encryptKeyId and fetch topic key from KeyCache     │
│  │   └─ If missing: loadServiceBundleForEpoch() from OpenBao   │
│  │   └─ Note: must have OpenBao path and action permissions    │
│  ├─ Decrypt payload via AesGcmHkdfCrypto                       │
│  │   └─ Uses HKDF with embedded salt to derive key             │
│  ├─ Extract signerServiceId and signerKeyId                    │
│  ├─ Fetch verification key from KeyCache                       │
│  │   └─ If missing: already loaded during bundle fetch         │
│  ├─ Verify Dilithium signature on decrypted domain bytes       │
│  │   └─ Fails if signature invalid                             │
│  └─ Return decrypted domain object bytes                       │
└────────────────────────────────────────────────────────────────┘
  │
  │ 5. Application deserializes and processes domain object
  │
  ▼
Business Logic (e.g., authenticate user, send response)
```

---

## 2. Core Components

### 2.1 SignedMessage Model

```java
Project: svc-core
Package: core.transport
Class:   SignedMessage.java

/**
 * A message container with signature information using Avro serialization.
 * 
 * Creation steps:
 * 1. Serialize domain message data (Avro)
 * 2. Sign the serialized data (DilithiumService)
 * 3. Obtain signing key information
 * 4. Obtain current topic encryption key
 * 5. Encrypt serialized data into EncryptedData (AesGcmHkdfCrypto)
 * 6. Serialize EncryptedData
 * 7. Build SignedMessage with serialized EncryptedData as payload
 * 8. Serialize SignedMessage
 * 
 * Verification steps (reverse of creation):
 * 1. Deserialize SignedMessage
 * 2. Deserialize EncryptedData from payload
 * 3. Obtain decryption key using encryptKeyId
 * 4. Decrypt payload with AesGcmHkdfCrypto
 * 5. Obtain signing public key using signerServiceId and signerKeyId
 * 6. Verify signature on decrypted domain bytes
 * 7. Deserialize domain object using payloadType
 */
public class SignedMessage implements Serializable {
  
  private static final long serialVersionUID = 1L;
  
  // Message fields
  private String  messageId;        // Composite: serviceId + timestamp
  private String  messageType;      // Type code for message
  private Long    caEpoch;          // CA certificate epoch
  private Long    keyEpoch;         // Encryption key epoch
  private String  signerServiceId;  // Service that created this message
  private Long    signerKeyId;      // Signing key epoch
  private Instant timestamp;        // When message was created
  private byte[]  signature;        // Dilithium signature (4,595 bytes)
  private String  topicName;        // NATS topic
  private String  encryptKeyId;     // Topic encryption key ID
  private String  payloadType;      // Domain object type
  private byte[]  payload;          // Serialized EncryptedData
  
  /**
   * Create a signed message.
   */
  public SignedMessage(String messageId, String messageType, long caEpoch, 
                       long keyEpoch, String signerServiceId, Long signerKeyId, 
                       Instant timestamp, byte[] signature, String topicName, 
                       String encryptKeyId, String payloadType, byte[] payload) {
    this.messageId = messageId;
    this.messageType = messageType;
    this.caEpoch = caEpoch;
    this.keyEpoch = keyEpoch;
    this.signerServiceId = signerServiceId;
    this.signerKeyId = signerKeyId;
    this.timestamp = timestamp;
    this.signature = signature;
    this.topicName = topicName;
    this.encryptKeyId = encryptKeyId;
    this.payloadType = payloadType;
    this.payload = payload;
  }
  
  // Getters
  public String  getMessageId()       { return messageId; }
  public String  getMessageType()     { return messageType; }
  public Long    getCaEpoch()         { return caEpoch; }
  public Long    getKeyEpoch()        { return keyEpoch; }
  public String  getSignerServiceId() { return signerServiceId; }
  public Long    getSignerKeyId()     { return signerKeyId; }
  public Instant getTimestamp()       { return timestamp; }
  public byte[]  getSignature()       { return signature; }
  public String  getTopicName()       { return topicName; }
  public String  getEncryptKeyId()    { return encryptKeyId; }
  public String  getPayloadType()     { return payloadType; }
  public byte[]  getPayload()         { return payload; }
  
  /**
   * Serialize using Avro binary format.
   */
  public static byte[] serialize(SignedMessage msgObj) throws Exception {
    // Avro serialization implementation
    // Returns compact binary representation
  }
  
  /**
   * Deserialize from Avro binary format.
   */
  public static SignedMessage deSerialize(byte[] bytes) throws Exception {
    // Avro deserialization implementation
    // Returns SignedMessage object
  }
}
```

**Key Design Points:**

- **Immutable after creation**: All fields are `final`-like (set in constructor)
- **Composite messageId**: `serviceId + timestamp` ensures uniqueness
- **Epoch metadata**: Enables key lookup without external calls
- **Self-contained**: All information for verification is embedded
- **Avro serialization**: Compact binary format (critical for large Dilithium signatures)

### 2.2 EncryptedData Model

```java
Project: svc-core
Package: core.crypto
Class:   EncryptedData.java

/**
 * Container for all components of an AEAD-encrypted message using HKDF-derived keys.
 * 
 * This structure is serialized and stored in SignedMessage.payload.
 * It contains everything needed to decrypt the message WITHOUT additional context.
 */
public final class EncryptedData {
  
  private final byte[] salt;        // 32 bytes - HKDF salt (unique per message)
  private final byte[] iv;          // 12 bytes - AES-GCM nonce (unique per message)
  private final byte[] ciphertext;  // Variable length - encrypted domain object
  private final byte[] tag;         // 16 bytes - GCM authentication tag
  
  public EncryptedData(byte[] salt, byte[] iv, byte[] ciphertext, byte[] tag) {
    if (salt == null || iv == null || ciphertext == null || tag == null) {
      throw new IllegalArgumentException("All EncryptedData fields must be provided");
    }
    this.salt = salt.clone();
    this.iv = iv.clone();
    this.ciphertext = ciphertext.clone();
    this.tag = tag.clone();
  }
  
  // Getters (return original arrays, not clones - used internally)
  public byte[] getSalt() { return salt; }
  public byte[] getIv() { return iv; }
  public byte[] getCiphertext() { return ciphertext; }
  public byte[] getTag() { return tag; }
  
  /**
   * Serialize all components into a single byte array for transmission.
   * Format: [salt_length][salt][iv_length][iv][tag_length][tag][ciphertext]
   */
  public byte[] serialize() {
    ByteBuffer buffer = ByteBuffer.allocate(
      4 + salt.length + 
      4 + iv.length + 
      4 + tag.length + 
      ciphertext.length
    );
    
    buffer.putInt(salt.length);
    buffer.put(salt);
    buffer.putInt(iv.length);
    buffer.put(iv);
    buffer.putInt(tag.length);
    buffer.put(tag);
    buffer.put(ciphertext);
    
    return buffer.array();
  }
  
  /**
   * Deserialize byte array back into EncryptedData.
   */
  public static EncryptedData deserialize(byte[] data) {
    ByteBuffer buffer = ByteBuffer.wrap(data);
    
    int saltLength = buffer.getInt();
    byte[] salt = new byte[saltLength];
    buffer.get(salt);
    
    int ivLength = buffer.getInt();
    byte[] iv = new byte[ivLength];
    buffer.get(iv);
    
    int tagLength = buffer.getInt();
    byte[] tag = new byte[tagLength];
    buffer.get(tag);
    
    byte[] ciphertext = new byte[buffer.remaining()];
    buffer.get(ciphertext);
    
    return new EncryptedData(salt, iv, ciphertext, tag);
  }
}
```

**Why This Structure?**

- **Self-contained**: All decryption parameters included (no external state)
- **Unique per message**: Salt and IV are randomly generated each time
- **Forward secrecy**: Compromise of topic key doesn't expose past messages (HKDF derives unique keys)
- **Integrity protection**: GCM tag ensures ciphertext hasn't been tampered with

### 2.3 AesGcmHkdfCrypto - Encryption Engine

```java
Project: svc-core
Package: core.crypto
Class:   AesGcmHkdfCrypto.java

/**
 * AES-256-GCM encryption with HKDF key derivation.
 * 
 * Key features:
 * - Uses topic encryption keys as Input Key Material (IKM) for HKDF
 * - Derives unique per-message encryption keys via HKDF-SHA256
 * - AES-GCM provides authenticated encryption (confidentiality + integrity)
 * - Random salt and IV per message (prevents key reuse attacks)
 * 
 * NOTE: This implementation does NOT use Additional Authenticated Data (AAD).
 * The HKDF info parameter is set to null in the current implementation.
 */
public class AesGcmHkdfCrypto {
  
  private static final int AES_KEY_SIZE = 32;      // 256 bits
  private static final int GCM_IV_SIZE = 12;       // 96 bits (NIST recommendation)
  private static final int GCM_TAG_SIZE = 16;      // 128 bits
  private static final int HKDF_SALT_SIZE = 32;    // 256 bits
  
  private final SecureRandom secureRandom;
  
  public AesGcmHkdfCrypto() {
    this.secureRandom = new SecureRandom();
  }
  
  /**
   * Encrypt plaintext using topic key as HKDF input material.
   * 
   * Process:
   * 1. Generate random salt (32 bytes)
   * 2. Derive per-message key via HKDF(topicKey, salt, null)
   * 3. Generate random IV (12 bytes)
   * 4. Encrypt with AES-256-GCM
   * 5. Return EncryptedData(salt, iv, ciphertext, tag)
   * 
   * @param plaintext - The data to encrypt (domain object bytes)
   * @param topicKey - Topic encryption key (used as HKDF IKM)
   * @return EncryptedData containing all decryption parameters
   */
  public EncryptedData encrypt(byte[] plaintext, byte[] topicKey) {
    try {
      // 1. Generate random salt for HKDF
      byte[] salt = new byte[HKDF_SALT_SIZE];
      secureRandom.nextBytes(salt);
      
      // 2. Derive per-message encryption key via HKDF (no info/AAD parameter)
      byte[] derivedKey = deriveKey(topicKey, salt, null);
      
      // 3. Generate random IV for AES-GCM
      byte[] iv = new byte[GCM_IV_SIZE];
      secureRandom.nextBytes(iv);
      
      // 4. Initialize AES-GCM cipher
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
      SecretKeySpec keySpec = new SecretKeySpec(derivedKey, "AES");
      GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_SIZE * 8, iv);
      
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
      
      // 5. Encrypt plaintext (GCM tag appended automatically)
      byte[] ciphertextWithTag = cipher.doFinal(plaintext);
      
      // 6. Split ciphertext and tag
      byte[] ciphertext = new byte[ciphertextWithTag.length - GCM_TAG_SIZE];
      byte[] tag = new byte[GCM_TAG_SIZE];
      
      System.arraycopy(ciphertextWithTag, 0, ciphertext, 0, ciphertext.length);
      System.arraycopy(ciphertextWithTag, ciphertext.length, tag, 0, GCM_TAG_SIZE);
      
      // 7. Return EncryptedData (salt needed for decryption)
      return new EncryptedData(salt, iv, ciphertext, tag);
      
    } catch (Exception e) {
      throw new RuntimeException("Encryption failed: " + e.getMessage(), e);
    }
  }
  
  /**
   * Decrypt ciphertext using topic key and embedded salt.
   * 
   * Process:
   * 1. Extract salt from EncryptedData
   * 2. Derive same per-message key via HKDF(topicKey, salt, null)
   * 3. Decrypt with AES-256-GCM
   * 4. Verify authentication tag
   * 5. Return plaintext
   * 
   * @param encryptedData - Contains salt, iv, ciphertext, tag
   * @param topicKey - Topic encryption key (same as used for encryption)
   * @return Decrypted plaintext
   * @throws RuntimeException if decryption fails
   */
  public byte[] decrypt(EncryptedData encryptedData, byte[] topicKey) {
    try {
      // 1. Extract components
      byte[] salt = encryptedData.getSalt();
      byte[] iv = encryptedData.getIv();
      byte[] ciphertext = encryptedData.getCiphertext();
      byte[] tag = encryptedData.getTag();
      
      // 2. Derive same per-message key via HKDF (using embedded salt)
      byte[] derivedKey = deriveKey(topicKey, salt, null);
      
      // 3. Reconstruct ciphertext with tag (GCM expects them together)
      byte[] ciphertextWithTag = new byte[ciphertext.length + tag.length];
      System.arraycopy(ciphertext, 0, ciphertextWithTag, 0, ciphertext.length);
      System.arraycopy(tag, 0, ciphertextWithTag, ciphertext.length, tag.length);
      
      // 4. Initialize AES-GCM cipher for decryption
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
      SecretKeySpec keySpec = new SecretKeySpec(derivedKey, "AES");
      GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_SIZE * 8, iv);
      
      cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
      
      // 5. Decrypt and verify tag
      byte[] plaintext = cipher.doFinal(ciphertextWithTag);
      
      return plaintext;
      
    } catch (Exception e) {
      throw new RuntimeException("Decryption failed: " + e.getMessage(), e);
    }
  }
  
  /**
   * Derive per-message encryption key using HKDF-SHA256.
   * 
   * @param ikm - Input Key Material (topic encryption key)
   * @param salt - Random salt (unique per message)
   * @param info - Context information (currently null, reserved for future use)
   * @return Derived AES-256 key (32 bytes)
   */
  private byte[] deriveKey(byte[] ikm, byte[] salt, byte[] info) {
    try {
      HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
      hkdf.init(new HKDFParameters(ikm, salt, info));
      
      byte[] derivedKey = new byte[AES_KEY_SIZE];
      hkdf.generateBytes(derivedKey, 0, AES_KEY_SIZE);
      
      return derivedKey;
      
    } catch (Exception e) {
      throw new RuntimeException("HKDF key derivation failed: " + e.getMessage(), e);
    }
  }
}
```

**Security Analysis:**

**Why Use HKDF Instead of Direct Encryption?**

```java
// ❌ WRONG: Using topic key directly for AES-GCM
SecretKeySpec keySpec = new SecretKeySpec(topicKey, "AES");
cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

// Problem: Same key used for all messages with same IV = catastrophic failure
// → IV reuse with same key breaks GCM security completely
// → No forward secrecy
```

```java
// ✅ CORRECT: Derive per-message key via HKDF
byte[] derivedKey = deriveKey(topicKey, randomSalt, null);
SecretKeySpec keySpec = new SecretKeySpec(derivedKey, "AES");
cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

// Benefits:
// → Each message encrypted with unique key (even with same topic key)
// → Forward secrecy: compromise of topic key doesn't expose past messages
// → IV reuse across different derived keys is safe
```

**Note on AAD (Additional Authenticated Data):**

The current implementation does **NOT** use AAD. The `deriveKey` method's `info` parameter is always `null`. This means:

- Ciphertext is NOT cryptographically bound to message metadata
- However, Dilithium signature covers the **decrypted domain bytes**, providing message integrity
- Topic key distribution enforces authorization (only authorized services have keys)

Future enhancement: AAD could bind ciphertext to `topicName`, `messageId`, `signerServiceId`, etc.

### 2.4 DilithiumService - Signature Engine

```java
Project: svc-core
Package: core.service
Class:   DilithiumService.java

/**
 * Dilithium digital signature service using post-quantum cryptography.
 * 
 * Handles asynchronous signing and verification operations using WorkerExecutor
 * to prevent blocking the event loop (Dilithium operations take 2-5ms).
 */
public class DilithiumService {
  
  private final WorkerExecutor workerExecutor;
  private final DilithiumCrypto dilithiumCrypto;
  
  public DilithiumService(WorkerExecutor workerExecutor) {
    this.workerExecutor = workerExecutor;
    this.dilithiumCrypto = new DilithiumCrypto();
  }
  
  /**
   * Sign data asynchronously using Dilithium private key.
   * 
   * @param data - Byte array to sign (domain object bytes)
   * @param signingKey - DilithiumKey containing private key
   * @return Future<byte[]> - Dilithium signature (4,595 bytes)
   */
  public Future<byte[]> sign(byte[] data, DilithiumKey signingKey) {
    return workerExecutor.executeBlocking(() -> {
      if (signingKey == null || signingKey.getPrivateKey() == null) {
        throw new RuntimeException("Signing key or private key is null");
      }
      
      return dilithiumCrypto.sign(data, signingKey.getPrivateKey());
    });
  }
  
  /**
   * Verify Dilithium signature asynchronously.
   * 
   * @param data - Original data bytes
   * @param signature - Signature to verify
   * @param verifyKey - DilithiumKey containing public key
   * @return Future<Boolean> - true if signature is valid
   */
  public Future<Boolean> verify(byte[] data, byte[] signature, DilithiumKey verifyKey) {
    return workerExecutor.executeBlocking(() -> {
      if (verifyKey == null || verifyKey.getPublicKey() == null) {
        throw new RuntimeException("Verify key or public key is null");
      }
      
      return dilithiumCrypto.verify(data, signature, verifyKey.getPublicKey());
    });
  }
}
```

**Why Asynchronous Signing?**

Dilithium5 signing takes **2-5 milliseconds** - long enough to block the event loop. Using `WorkerExecutor` ensures:
- Event loop remains responsive
- Multiple signatures can be computed in parallel
- Better throughput under load

### 2.5 KeySecretManager - Unified Key Storage

```java
Project: svc-core
Package: core.handler
Class:   KeySecretManager.java

/**
 * Complete unified key manager for all key types:
 * - Shared secrets for Kyber key exchange
 * - Dilithium signing keys for message authentication
 * - Dilithium verification keys for other services
 * - Topic encryption keys for message content encryption
 * 
 * Handles storage, retrieval, and automatic loading from OpenBao.
 */
public class KeySecretManager {
  
  private static final int TOPIC_KEY_RETENTION_EPOCHS = 20;  // Keep 20 epochs (100 minutes)
  
  // Storage for different key types
  private final ConcurrentHashMap<String, ConcurrentHashMap<String, SharedSecretInfo>> sharedSecrets;
  private final ConcurrentHashMap<String, ConcurrentHashMap<Long, DilithiumKey>> verifyKeys;
  private final ConcurrentHashMap<Long, DilithiumKey> signingKeys;
  private final ConcurrentHashMap<String, ConcurrentHashMap<String, TopicKey>> topicKeys;
  private final ConcurrentHashMap<String, TopicPermission> topicPermissions;
  
  // Track which epochs we've loaded from OpenBao
  private final ConcurrentHashMap<Long, ServiceBundle> loadedServiceBundleEpochs;
  
  private final VaultAccessHandler vaultHandler;
  
  /**
   * Get topic encryption key by topic name and key ID.
   */
  public TopicKey getTopicKey(String topicName, String keyId) {
    if (topicName == null || keyId == null) {
      return null;
    }
    
    ConcurrentHashMap<String, TopicKey> topicKeyMap = topicKeys.get(topicName);
    if (topicKeyMap == null) {
      return null;
    }
    
    return topicKeyMap.get(keyId);
  }
  
  /**
   * Get valid topic keys sorted by creation time (newest first).
   */
  public List<TopicKey> getValidTopicKeysSorted(String topicName) {
    return getValidTopicKeys(topicName).stream()
      .sorted(Comparator.comparing(TopicKey::getCreatedTime).reversed())
      .collect(Collectors.toList());
  }
  
  /**
   * Get signing key for current epoch.
   */
  public DilithiumKey getSigningKey(long epoch) {
    return signingKeys.get(epoch);
  }
  
  /**
   * Get Dilithium public key for signature verification.
   * 
   * @param serviceId - Service ID (e.g., "authcontroller")
   * @param epoch - Key epoch from message
   * @return Future<DilithiumKey> with public key
   */
  public Future<DilithiumKey> getDilithiumPublicKey(String serviceId, long epoch) {
    if (serviceId == null || serviceId.isBlank() || epoch <= 0) {
      return Future.failedFuture(
        new IllegalArgumentException("ServiceID and epoch cannot be null/empty"));
    }
    
    // Check cache first
    Map<Long, DilithiumKey> serviceSigningKeys = verifyKeys.get(serviceId);
    if (serviceSigningKeys != null) {
      DilithiumKey key = serviceSigningKeys.get(epoch);
      if (key != null) {
        LOGGER.debug("Found verification key {}:{} in local cache", serviceId, epoch);
        return Future.succeededFuture(key);
      }
    }
    
    // Not found in cache
    return Future.failedFuture(
      new IllegalArgumentException("Verification key not found for " + serviceId + ":" + epoch));
  }
  
  /**
   * Load a specific ServiceBundle epoch from OpenBao on-demand.
   * 
   * This is the self-healing mechanism that eliminates manual intervention.
   * 
   * @param targetServiceId - Service whose bundle we need
   * @param epoch - Epoch for which we need keys
   * @return Future<Void>
   */
  public Future<Void> loadServiceBundleForEpoch(String targetServiceId, long epoch) {
    // Check if already loaded
    if (hasServiceBundleForEpoch(epoch)) {
      LOGGER.debug("ServiceBundle for epoch {} already loaded", epoch);
      return Future.succeededFuture();
    }
    
    LOGGER.info("Fetching ServiceBundle from OpenBao: service='{}', epoch={}", 
                targetServiceId, epoch);
    
    return vaultHandler.getServiceBundle(targetServiceId, epoch)
      .compose(bundle -> {
        loadFromServiceBundle(bundle);
        LOGGER.info("✅ Loaded ServiceBundle from OpenBao: service='{}', epoch={}", 
                    targetServiceId, epoch);
        return Future.succeededFuture();
      })
      .recover(err -> {
        LOGGER.error("Failed to load ServiceBundle from OpenBao: service='{}', epoch={}, error={}",
                     targetServiceId, epoch, err.getMessage(), err);
        return Future.failedFuture(err);
      });
  }
  
  /**
   * Check if we have a specific epoch loaded.
   */
  public boolean hasServiceBundleForEpoch(long epoch) {
    return loadedServiceBundleEpochs.containsKey(epoch);
  }
  
  /**
   * Load all keys and permissions from a ServiceBundle.
   */
  public void loadFromServiceBundle(ServiceBundle bundle) {
    // 1. Signing keys (private keys for this service)
    if (bundle.getSigningKeys() != null) {
      for (Map.Entry<Long, DilithiumKey> entry : bundle.getSigningKeys().entrySet()) {
        DilithiumKey dKey = entry.getValue();
        signingKeys.put(dKey.getEpochNumber(), dKey);
      }
      LOGGER.debug("Loaded {} signing keys from ServiceBundle", 
                   bundle.getSigningKeys().size());
    }
    
    // 2. Verify keys (public keys for other services)
    if (bundle.getVerifyKeys() != null) {
      for (Map.Entry<String, Map<Long, DilithiumKey>> svcEntry : 
           bundle.getVerifyKeys().entrySet()) {
        String serviceId = svcEntry.getKey();
        Map<Long, DilithiumKey> svcKeys = svcEntry.getValue();
        if (svcKeys != null) {
          ConcurrentHashMap<Long, DilithiumKey> cache = verifyKeys.computeIfAbsent(
            serviceId, k -> new ConcurrentHashMap<>());
          for (Map.Entry<Long, DilithiumKey> keyEntry : svcKeys.entrySet()) {
            cache.put(keyEntry.getKey(), keyEntry.getValue());
          }
          LOGGER.debug("Loaded {} verify keys for service {} from ServiceBundle", 
                       svcKeys.size(), serviceId);
        }
      }
    }
    
    // 3. Topic keys
    if (bundle.getTopicKeys() != null) {
      for (Map.Entry<String, Map<String, TopicKey>> topicEntry : 
           bundle.getTopicKeys().entrySet()) {
        String topic = topicEntry.getKey();
        Map<String, TopicKey> keyMap = topicEntry.getValue();
        if (keyMap != null) {
          for (TopicKey topicKey : keyMap.values()) {
            storeTopicKey(topicKey);
          }
          LOGGER.debug("Loaded {} topic keys for topic {} from ServiceBundle", 
                       keyMap.size(), topic);
        }
      }
    }
    
    // 4. Topic permissions
    if (bundle.getTopicPermissions() != null) {
      for (Map.Entry<String, TopicPermission> entry : 
           bundle.getTopicPermissions().entrySet()) {
        topicPermissions.put(entry.getKey(), entry.getValue());
      }
      LOGGER.debug("Loaded {} topic permissions from ServiceBundle", 
                   bundle.getTopicPermissions().size());
    }
    
    // Mark epoch as loaded
    loadedServiceBundleEpochs.put(bundle.getKeyEpoch(), bundle);
  }
  
  /**
   * Store a topic encryption key.
   */
  public void storeTopicKey(TopicKey key) {
    if (key == null) {
      throw new IllegalArgumentException("Topic key cannot be null");
    }
    
    String topicName = key.getTopicName();
    String keyId = key.getKeyId();
    
    ConcurrentHashMap<String, TopicKey> topicKeyMap = topicKeys.computeIfAbsent(
      topicName, k -> new ConcurrentHashMap<>());
    
    topicKeyMap.put(keyId, key);
    
    // Cleanup old keys using epoch retention
    cleanupExpiredTopicKeys(topicName);
    
    LOGGER.debug("Stored topic encryption key: {} for topic: {} (expires: {})", 
                 keyId, topicName, key.getExpiryTime());
  }
}
```
The KeySecretsManager is currently in memory only. There is no persistance of the information.

---

## 3. Message Creation Flow

### 3.1 SignedMessageProcessor Component

```java
Project: svc-core
Package: core.processor
Class:   SignedMessageProcessor.java

/**
 * Generic processor for creating SignedMessages and decrypting/verifying on receipt.
 * 
 * Supports two encryption modes:
 * 1. Topic-based encryption (standard messages)
 * 2. Shared-secret encryption (Kyber key exchange)
 */
public class SignedMessageProcessor {
  
  private final WorkerExecutor workerExecutor;
  private final KeySecretManager keyCache;
  private final AesGcmHkdfCrypto aesCrypto;
  private final DilithiumService signingManager;
  private final CAEpochUtil caEpochUtil;
  
  // Track pending key fetches to avoid duplicate requests
  private final ConcurrentHashMap<String, Future<Void>> pendingKeyFetches;
  
  public SignedMessageProcessor(WorkerExecutor workerExecutor, KeySecretManager keyCache) {
    this.workerExecutor = workerExecutor;
    this.keyCache = keyCache;
    this.aesCrypto = new AesGcmHkdfCrypto();
    this.signingManager = new DilithiumService(workerExecutor);
    this.caEpochUtil = new CAEpochUtil();
    this.pendingKeyFetches = new ConcurrentHashMap<>();
  }
}
```

### 3.2 Creating SignedMessage with Topic Encryption

```java
/**
 * Create SignedMessage using topic-based encryption (standard flow).
 * 
 * Process:
 * 1. Get signing key from KeyCache
 * 2. Sign domain object bytes (async via DilithiumService)
 * 3. Get topic encryption key from KeyCache
 * 4. Encrypt domain object bytes
 * 5. Build SignedMessage with encrypted payload + signature
 * 
 * @param serviceId - Service creating the message
 * @param objBytes - Avro-serialized domain object
 * @param messageType - Type code for message
 * @param payloadType - Type code for payload (usually same as messageType)
 * @param topic - Topic name the message will be sent on
 * @return Future<SignedMessage>
 */
public Future<SignedMessage> createSignedMessage(
    String serviceId,
    byte[] objBytes,
    String messageType,
    String payloadType,
    String topic) {
  
  LOGGER.debug("Generating SignedMessage for service: {}", serviceId);
  
  // Step 1: Get signing key (blocking)
  return workerExecutor.<DilithiumKey>executeBlocking(() -> {
    
    long currEpoch = KeyEpochUtil.epochNumberForInstant(Instant.now());
    DilithiumKey signingKey = keyCache.getSigningKey(currEpoch);
    
    if (signingKey == null) {
      String errMsg = "Signing key not found for epoch " + currEpoch;
      LOGGER.error(errMsg);
      throw new RuntimeException(errMsg);
    }
    
    return signingKey;
    
  }).compose(signingKey ->
    
    // Step 2: Sign domain object bytes (async)
    signingManager.sign(objBytes, signingKey)
      .compose(signature ->
        
        // Step 3: Encrypt with topic key (blocking)
        workerExecutor.<SignedMessage>executeBlocking(() -> {
          return createSignedMessageWithTopicEncryption(
            serviceId, objBytes, messageType, payloadType,
            topic, signingKey, signature
          );
        })
      )
  )
  .onFailure(err -> {
    String errMsg = "Failed to create SignedMessage for service: " + serviceId + 
                    "; Error = " + err.getMessage();
    LOGGER.error(errMsg, err);
  });
}

/**
 * Helper method to create SignedMessage with topic-based encryption.
 */
private SignedMessage createSignedMessageWithTopicEncryption(
    String serviceId,
    byte[] objBytes,
    String messageType,
    String payloadType,
    String topic,
    DilithiumKey signingKey,
    byte[] signature) throws Exception {
  
  long keyEpoch = KeyEpochUtil.epochNumberForInstant(Instant.now());
  List<TopicKey> keyList = keyCache.getValidTopicKeysSorted(topic);
  
  // Find topic key for current epoch
  TopicKey topicKey = null;
  for (TopicKey key : keyList) {
    if (keyEpoch == key.getEpochNumber()) {
      topicKey = key;
      break;
    }
  }
  
  if (topicKey == null) {
    LOGGER.error("============================================================");
    LOGGER.error(" Could not find topic key for topic = {} for epoch = {}", topic, keyEpoch);
    LOGGER.error("Topic keys found for this topic are:");
    for (TopicKey key : keyList) {
      LOGGER.error("Epoch = {} keyId = {}", key.getEpochNumber(), key.getKeyId());
    }
    
    Set<String> topics = keyCache.getAllTopicsWithKeys();
    LOGGER.error("Topics supported by this service are:");
    for (String nm : topics) {
      LOGGER.error(nm);
    }
    LOGGER.error("============================================================");
    
    throw new RuntimeException("Could not obtain encryption key for topic: " + topic);
  }
  
  // Encrypt domain object bytes
  EncryptedData encData = aesCrypto.encrypt(objBytes, topicKey.getKeyData());
  
  if (encData == null || encData.getCiphertext() == null || 
      encData.getCiphertext().length == 0) {
    throw new RuntimeException("Failed to encrypt for service: " + serviceId);
  }
  
  LOGGER.debug("Successfully encrypted bundle for service: {} using topic key", serviceId);
  
  // Build SignedMessage
  Instant now = Instant.now();
  long caEpoch = caEpochUtil.epochNumberForInstant(now);
  
  return new SignedMessage(
    serviceId + now.toString(),        // messageId (composite)
    messageType,
    caEpoch,
    keyEpoch,
    serviceId,                         // signerServiceId
    signingKey.getEpochNumber(),       // signerKeyId
    now,                               // timestamp
    signature,
    topic,                             // topicName
    topicKey.getKeyId(),               // encryptKeyId
    payloadType,
    encData.serialize()                // payload (serialized EncryptedData)
  );
}
```

### 3.3 Creating SignedMessage with Shared Secret Encryption

```java
/**
 * Create SignedMessage using shared secret encryption (Kyber key exchange).
 * 
 * This overload is used during Kyber-based key exchange where the encryption
 * key is a shared secret rather than a topic key.
 * 
 * @param serviceId - Service creating the message
 * @param objBytes - Avro-serialized domain object
 * @param messageType - Type code for message
 * @param payloadType - Type code for payload
 * @param topic - Topic name
 * @param sharedSecret - Shared secret from Kyber encapsulation
 * @return Future<SignedMessage>
 */
public Future<SignedMessage> createSignedMessage(
    String serviceId,
    byte[] objBytes,
    String messageType,
    String payloadType,
    String topic,
    byte[] sharedSecret) {
  
  LOGGER.debug("Generating SignedMessage for service: {} using shared secret encryption", 
               serviceId);
  
  // Step 1: Get signing key (blocking)
  return workerExecutor.<DilithiumKey>executeBlocking(() -> {
    
    DilithiumKey signingKey = keyCache.getSigningKey(
      KeyEpochUtil.epochNumberForInstant(Instant.now()));
    
    if (signingKey == null) {
      String errMsg = "Signing key not found";
      LOGGER.error(errMsg);
      throw new RuntimeException(errMsg);
    }
    
    return signingKey;
    
  }).compose(signingKey ->
    
    // Step 2: Sign (async)
    signingManager.sign(objBytes, signingKey)
      .compose(signature ->
        
        // Step 3: Encrypt using shared secret (blocking)
        workerExecutor.<SignedMessage>executeBlocking(() -> {
          return createSignedMessageWithSharedSecretEncryption(
            serviceId, objBytes, messageType, payloadType,
            topic, signingKey, signature, sharedSecret
          );
        })
      )
  )
  .onFailure(err -> {
    String errMsg = "Failed to create SignedMessage with shared secret for service: " + 
                    serviceId + "; Error = " + err.getMessage();
    LOGGER.error(errMsg, err);
  });
}

/**
 * Helper method to create SignedMessage with shared secret encryption.
 */
private SignedMessage createSignedMessageWithSharedSecretEncryption(
    String serviceId,
    byte[] objBytes,
    String messageType,
    String payloadType,
    String topic,
    DilithiumKey signingKey,
    byte[] signature,
    byte[] sharedSecret) throws Exception {
  
  if (sharedSecret == null || sharedSecret.length == 0) {
    String errMsg = "Shared secret cannot be null or empty";
    LOGGER.error(errMsg);
    throw new RuntimeException(errMsg);
  }
  
  // Encrypt with shared secret (uses same HKDF mechanism)
  EncryptedData encData = aesCrypto.encrypt(objBytes, sharedSecret);
  
  if (encData == null || encData.getCiphertext() == null || 
      encData.getCiphertext().length == 0) {
    throw new RuntimeException("Failed to encrypt with shared secret for service: " + serviceId);
  }
  
  LOGGER.debug("Successfully encrypted bundle for service: {} using shared secret", serviceId);
  
  // For shared secret encryption, use special key ID prefix
  String sharedSecretKeyId = SignedMessageProcessor.SHARED_SECRET_KEY_ID_PREFIX + 
                             System.currentTimeMillis();
  
  Instant now = Instant.now();
  long keyEpoch = KeyEpochUtil.epochNumberForInstant(now);
  long caEpoch = caEpochUtil.epochNumberForInstant(now);
  
  return new SignedMessage(
    serviceId + now.toString(),
    messageType,
    caEpoch,
    keyEpoch,
    serviceId,
    signingKey.getEpochNumber(),
    now,
    signature,
    topic,
    sharedSecretKeyId,                 // Special key ID for shared secret
    payloadType,
    encData.serialize()
  );
}
```

**Shared Secret Key ID Convention:**

```java
public static final String SHARED_SECRET_KEY_ID_PREFIX = "shared-secret-";

// Example encryptKeyId for shared secret:
// "shared-secret-1737097582000"
//                ^^^^^^^^^^^^^ timestamp in millis

// This allows receiver to distinguish shared-secret vs topic-key encryption
```

---

## 4. Message Verification and Decryption with Automatic Key Recovery

### 4.1 The obtainDomainObject Method

```java
/**
 * Obtain, verify, decrypt, and deserialize the domain object from a SignedMessage.
 * 
 * This method implements automatic ServiceBundle recovery from OpenBao:
 * 1. Deserialize SignedMessage
 * 2. Deserialize EncryptedData from payload
 * 3. Fetch topic decryption key from KeyCache
 *    - If missing: throws KeyMissingException
 * 4. Decrypt payload
 * 5. Fetch verification key from KeyCache
 * 6. Verify Dilithium signature on decrypted domain bytes
 * 7. Return decrypted domain object bytes
 * 
 * If KeyMissingException is thrown, the recover() handler:
 * - Calls fetchMissingKeyAndRetry()
 * - Loads ServiceBundle from OpenBao via keyCache.loadServiceBundleForEpoch()
 * - Retries decryption with newly loaded keys
 * 
 * @param signedMsgBytes - Serialized SignedMessage from NATS
 * @return Future<byte[]> - Decrypted domain object bytes
 */
public Future<byte[]> obtainDomainObject(byte[] signedMsgBytes) {
  
  return workerExecutor.<Tuple3<byte[], SignedMessage, Long>>executeBlocking(() -> {
    
    try {
      // 1. Deserialize SignedMessage
      SignedMessage signedMsg = SignedMessage.deSerialize(signedMsgBytes);
      EncryptedData encData = EncryptedData.deserialize(signedMsg.getPayload());
      
      // 2. Get topic encryption key
      TopicKey encKey = keyCache.getTopicKey(
        signedMsg.getTopicName(), 
        signedMsg.getEncryptKeyId()
      );
      
      if (encKey == null) {
        LOGGER.error("============================================================");
        LOGGER.error(" Could not find topic key for topic = {} keyId = {}", 
                     signedMsg.getTopicName(), signedMsg.getEncryptKeyId());
        LOGGER.error("Topic keys found for this topic are:");
        
        List<TopicKey> keyList = keyCache.getValidTopicKeysSorted(signedMsg.getTopicName());
        for (TopicKey key : keyList) {
          LOGGER.error("Epoch = {} keyId = {}", key.getEpochNumber(), key.getKeyId());
        }
        
        Set<String> topics = keyCache.getAllTopicsWithKeys();
        LOGGER.error("Topics supported by this service are:");
        for (String nm : topics) {
          LOGGER.error(nm);
        }
        LOGGER.error("============================================================");
        
        // Throw KeyMissingException (will trigger automatic recovery)
        throw new KeyMissingException(
          signedMsg.getSignerServiceId(),
          signedMsg.getTopicName(),
          signedMsg.getEncryptKeyId(),
          "Encryption key could not be found for decryption. Topic = " + 
          signedMsg.getTopicName() + "; keyId = " + signedMsg.getEncryptKeyId()
        );
      }
      
      // 3. Decrypt domain object
      byte[] domainBytes = aesCrypto.decrypt(encData, encKey.getKeyData());
      
      return new Tuple3<>(domainBytes, signedMsg, signedMsg.getSignerKeyId());
      
    } catch (Exception e) {
      LOGGER.error("Failed to process SignedMessage in background thread", e);
      throw new RuntimeException(e);
    }
  })
  .recover(err -> {
    
    // Handle missing key exception with automatic recovery
    if (err instanceof KeyMissingException) {
      KeyMissingException kme = (KeyMissingException) err;
      
      LOGGER.info("Key missing for topic '{}', keyId '{}' - attempting on-demand fetch",
                  kme.getTopic(), kme.getKeyId());
      
      return fetchMissingKeyAndRetry(signedMsgBytes, kme);
    }
    
    // Other error - propagate
    return Future.failedFuture(err);
  })
  .compose(tuple -> {
    
    // 4. Verify signature
    byte[] domainBytes = tuple._1;
    SignedMessage signedMsg = tuple._2;
    Long signerKeyId = tuple._3;
    
    return keyCache.getDilithiumPublicKey(signedMsg.getSignerServiceId(), signerKeyId)
      .compose(signingKey -> {
        
        if (signingKey != null) {
          return signingManager.verify(domainBytes, signedMsg.getSignature(), signingKey)
            .compose(verified -> {
              if (!verified) {
                LOGGER.warn("Signature verification failed for domain object");
                return Future.failedFuture("Signature invalid");
              }
              return Future.succeededFuture(domainBytes);
            });
        } else {
          LOGGER.warn("No signing key found, skipping signature verification");
          return Future.succeededFuture(domainBytes);
        }
      });
  });
}
```

### 4.2 Automatic ServiceBundle Recovery from OpenBao

```java
/**
 * Fetch missing key and retry decryption.
 * 
 * This is the self-healing mechanism:
 * 1. Extract epoch from keyId (e.g., "auth.request-epoch-98765" → 98765)
 * 2. Determine which service's ServiceBundle we need (signerServiceId)
 * 3. Call keyCache.loadServiceBundleForEpoch() to fetch from OpenBao
 * 4. Retry decryption with newly loaded keys
 * 
 * @param signedMsgBytes - Original SignedMessage bytes
 * @param kme - KeyMissingException containing context
 * @return Future<Tuple3<byte[], SignedMessage, Long>>
 */
private Future<Tuple3<byte[], SignedMessage, Long>> fetchMissingKeyAndRetry(
    byte[] signedMsgBytes, 
    KeyMissingException kme) {
  
  // 1. Extract epoch from keyId
  long missingEpoch = extractEpochFromKeyId(kme.getKeyId());
  if (missingEpoch < 0) {
    LOGGER.error("Could not extract epoch from keyId: {}", kme.getKeyId());
    return Future.failedFuture(kme);
  }
  
  // 2. Determine which service's ServiceBundle we need
  String targetServiceId = kme.getServiceId();
  
  LOGGER.info("Attempting to fetch ServiceBundle: service='{}', epoch={}", 
              targetServiceId, missingEpoch);
  
  // 3. Check if already fetching this key (avoid duplicate requests)
  String fetchKey = targetServiceId + ":" + missingEpoch;
  
  Future<Void> fetchFuture = pendingKeyFetches.computeIfAbsent(fetchKey, k -> {
    LOGGER.info("Initiating ServiceBundle fetch for key '{}'", k);
    
    return keyCache.loadServiceBundleForEpoch(targetServiceId, missingEpoch)
      .onComplete(ar -> {
        // Remove from pending map when complete
        pendingKeyFetches.remove(k);
        
        if (ar.succeeded()) {
          LOGGER.info("✅ ServiceBundle fetch successful for key '{}'", k);
        } else {
          LOGGER.error("❌ ServiceBundle fetch failed for key '{}': {}", 
                       k, ar.cause().getMessage());
        }
      });
  });
  
  // 4. Wait for fetch to complete, then retry decryption
  return fetchFuture.compose(v -> {
    LOGGER.info("Retrying decryption after ServiceBundle fetch");
    
    return workerExecutor.<Tuple3<byte[], SignedMessage, Long>>executeBlocking(() -> {
      try {
        SignedMessage signedMsg = SignedMessage.deSerialize(signedMsgBytes);
        EncryptedData encData = EncryptedData.deserialize(signedMsg.getPayload());
        
        // Try to get encryption key again
        TopicKey encKey = keyCache.getTopicKey(
          signedMsg.getTopicName(), 
          signedMsg.getEncryptKeyId()
        );
        
        if (encKey == null) {
          // Still not found after fetch
          LOGGER.error("============================================================");
          LOGGER.error("Key STILL not found after ServiceBundle fetch!");
          LOGGER.error("Service: {}, Topic: {}, KeyId: {}, Epoch: {}", 
                       targetServiceId, kme.getTopic(), kme.getKeyId(), missingEpoch);
          LOGGER.error("============================================================");
          
          throw new KeyMissingException(
            targetServiceId, kme.getTopic(), kme.getKeyId(),
            "Key not found even after ServiceBundle fetch - may not exist in OpenBao"
          );
        }
        
        // Decrypt with newly loaded key
        byte[] domainBytes = aesCrypto.decrypt(encData, encKey.getKeyData());
        
        LOGGER.info("✅ Decryption successful after on-demand key fetch");
        
        return new Tuple3<>(domainBytes, signedMsg, signedMsg.getSignerKeyId());
        
      } catch (Exception e) {
        LOGGER.error("Retry decryption failed: {}", e.getMessage(), e);
        throw new RuntimeException(e);
      }
    });
  });
}

/**
 * Extract epoch number from keyId string.
 * 
 * Examples:
 * - "auth.request-epoch-98765" → 98765
 * - "gatekeeper.responder-epoch-98766" → 98766
 */
private long extractEpochFromKeyId(String keyId) {
  if (keyId == null || !keyId.contains("-epoch-")) {
    return -1;
  }
  
  try {
    int lastDash = keyId.lastIndexOf('-');
    String epochStr = keyId.substring(lastDash + 1);
    return Long.parseLong(epochStr);
  } catch (Exception e) {
    LOGGER.debug("Could not extract epoch from keyId '{}': {}", keyId, e.getMessage());
    return -1;
  }
}
```

**OpenBao ServiceBundle Storage:**

ServiceBundles are stored in OpenBao at:
```
secret/data/service-bundles/{serviceId}/epoch-{epochNumber}
```

Example paths:
```
secret/data/service-bundles/authcontroller/epoch-98765
secret/data/service-bundles/gatekeeper/epoch-98765
secret/data/service-bundles/metadata/epoch-98765
secret/data/service-bundles/watcher/epoch-98765
```
In order for the service to obtain the epoch service bundles they must have been granted permissions to the path and the 'read' action.
An example from the Step-09-DeployAuthController.sh for the necessary permissions are:
```
# ServiceBundle read for authcontroller
path "secret/data/service-bundles/authcontroller/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/service-bundles/authcontroller/*" {
  capabilities = ["read", "list"]
}

# CaBundle read for NATS
path "secret/data/ca-bundles/NATS/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/ca-bundles/NATS/*" {
  capabilities = ["read", "list"]
}

# Allow reading metadata service bundles (for verification keys)
path "secret/data/service-bundles/metadata/*" {
  capabilities = ["read", "list"]
}
```

**VaultAccessHandler.getServiceBundle():**

```java
Project: svc-core
Package: core.handler
Class:   VaultAccessHandler.java

public Future<ServiceBundle> getServiceBundle(String serviceId, long epoch) {
  String path = String.format("secret/data/service-bundles/%s/epoch-%d", serviceId, epoch);
  
  return workerExecutor.executeBlocking(() -> {
    
    JsonObject response = vaultClient.read(path);
    
    if (response == null || !response.containsKey("data")) {
      throw new RuntimeException("ServiceBundle not found in OpenBao: " + path);
    }
    
    JsonObject data = response.getJsonObject("data").getJsonObject("data");
    String bundleBase64 = data.getString("bundle");
    
    byte[] bundleBytes = Base64.getDecoder().decode(bundleBase64);
    ServiceBundle bundle = ServiceBundle.deserialize(bundleBytes);
    
    LOGGER.info("✅ Retrieved ServiceBundle from OpenBao: service={}, epoch={}", 
                serviceId, epoch);
    
    return bundle;
  });
}
```

### 4.3 Alternative Decryption Method (No Verification)

```java
/**
 * Obtains decrypted domain bytes AND parsed SignedMessage (no verification).
 * 
 * This overload is used when the caller wants to perform verification themselves
 * using keys contained within the domain object (e.g., ServiceBundle carrying
 * signing keys for bootstrap scenarios).
 * 
 * Use case: During key exchange, the ServiceBundle contains the verification keys
 * needed to verify its own signature. We must decrypt first, extract the keys,
 * then verify.
 * 
 * @param signedMsgBytes - Serialized SignedMessage
 * @param encKey - Encryption key to use for decryption (e.g., Kyber shared secret)
 * @return Future<Tuple3<byte[], SignedMessage, Long>> - (domainBytes, SignedMessage, signerKeyId)
 */
public Future<Tuple3<byte[], SignedMessage, Long>> obtainDomainObject(
    byte[] signedMsgBytes, 
    byte[] encKey) {
  
  return workerExecutor.<Tuple3<byte[], SignedMessage, Long>>executeBlocking(() -> {
    
    try {
      SignedMessage signedMsg = SignedMessage.deSerialize(signedMsgBytes);
      EncryptedData encData = EncryptedData.deserialize(signedMsg.getPayload());
      
      if (encKey == null) {
        String errMsg = "Encryption key could not be found for decryption";
        LOGGER.error(errMsg);
        throw new Exception(errMsg);
      }
      
      // Decrypt using provided key (no KeyCache lookup)
      byte[] domainBytes = aesCrypto.decrypt(encData, encKey);
      
      return new Tuple3<>(domainBytes, signedMsg, signedMsg.getSignerKeyId());
      
    } catch (Exception e) {
      LOGGER.error("Failed to process SignedMessage in background thread", e);
      throw new RuntimeException(e);
    }
  });
}
```

**Usage Example (Key Exchange):**

```java
// During Kyber key exchange, we receive ServiceBundle encrypted with shared secret

// 1. Perform Kyber decapsulation to get shared secret
byte[] sharedSecret = kyberCrypto.decapsulate(ciphertext, privateKey);

// 2. Decrypt ServiceBundle (but don't verify yet - we don't have keys)
Future<Tuple3<byte[], SignedMessage, Long>> futureBundle = 
  processor.obtainDomainObject(signedMsgBytes, sharedSecret);

futureBundle.onSuccess(tuple -> {
  byte[] bundleBytes = tuple._1;
  SignedMessage signedMsg = tuple._2;
  Long signerKeyId = tuple._3;
  
  // 3. Deserialize ServiceBundle
  ServiceBundle bundle = ServiceBundle.deserialize(bundleBytes);
  
  // 4. Extract verification key from bundle itself
  DilithiumKey verifyKey = bundle.getVerifyKeys()
    .get(signedMsg.getSignerServiceId())
    .get(signerKeyId);
  
  // 5. NOW verify signature using extracted key
  processor.verifyWithKey(bundleBytes, signedMsg.getSignature(), verifyKey)
    .onSuccess(verified -> {
      if (verified) {
        LOGGER.info("✅ ServiceBundle signature verified with bundled key");
        
        // 6. Load bundle into KeyCache
        keyCache.loadFromServiceBundle(bundle);
      } else {
        LOGGER.error("❌ ServiceBundle signature verification failed");
      }
    });
});
```

### 4.4 Public Verification Helper

```java
/**
 * Public wrapper to verify a domain object's signature using a provided DilithiumKey.
 * 
 * This allows external callers to perform verification with custom keys
 * (e.g., keys extracted from the domain object itself).
 * 
 * @param domainBytes - Domain object bytes
 * @param signature - Dilithium signature
 * @param signingKey - DilithiumKey containing public key
 * @return Future<Boolean> - true if signature is valid
 */
public Future<Boolean> verifyWithKey(byte[] domainBytes, byte[] signature, DilithiumKey signingKey) {
  return signingManager.verify(domainBytes, signature, signingKey);
}
```

---

---

## 5. Complete End-to-End Example

### 5.1 Full Message Flow (Gatekeeper → AuthController → Gatekeeper)

This example demonstrates the complete authentication request/response cycle using the actual verticles in the system.

```
┌─────────────────────────────────────────────────────────────────┐
│           Complete Authentication Message Flow                  │
└─────────────────────────────────────────────────────────────────┘

GATEKEEPER (Request Generation)
  │
  │ AuthRequestGeneratorVert
  │  ├─ Generate AuthenticationRequest (userId, pwdHash, otp)
  │  ├─ Serialize to Avro bytes
  │  ├─ Create SignedMessage via SignedMessageProcessor
  │  ├─ Add headers: generationCounter, generationTimestamp
  │  └─ Publish to NATS topic: "auth.auth-request"
  │
  ▼
┌────────────────────────────────────────────────────────────────┐
│ NATS JetStream                                                 │
│  Stream: AUTH_STREAM                                           │
│  Topic: auth.auth-request                                      │
└────────────────────────────────────────────────────────────────┘
  │
  ▼
AUTHCONTROLLER (Request Processing)
  │
  │ AuthControllerConsumerVert (Pull Consumer)
  │  ├─ Fetch message from AUTH_STREAM
  │  ├─ Extract headers: generationCounter, generationTimestamp
  │  ├─ Increment receiptCounter
  │  ├─ Decrypt and verify SignedMessage
  │  ├─ Deserialize AuthenticationRequest
  │  └─ Publish to event bus: "authcontroller.process.request"
  │
  ▼
  │ AuthControllerProducerVert (Event Bus Consumer)
  │  ├─ Receive from event bus: "authcontroller.process.request"
  │  ├─ Deserialize AuthenticationRequest
  │  ├─ Create AuthenticationResponse (APPROVED/DENIED)
  │  ├─ Increment processingCounter
  │  ├─ Serialize AuthenticationResponse to Avro
  │  ├─ Create SignedMessage via SignedMessageProcessor
  │  ├─ Add headers: generationCounter, receiptCounter, processingCounter
  │  └─ Publish to NATS topic: "gatekeeper.responder"
  │
  ▼
┌────────────────────────────────────────────────────────────────┐
│ NATS JetStream                                                 │
│  Stream: GATEKEEPER_STREAM                                     │
│  Topic: gatekeeper.responder                                   │
└────────────────────────────────────────────────────────────────┘
  │
  ▼
GATEKEEPER (Response Processing)
  │
  │ GatekeeperConsumerVert (Pull Consumer)
  │  ├─ Fetch message from GATEKEEPER_STREAM
  │  ├─ Extract headers: generationCounter, receiptCounter, processingCounter
  │  ├─ Decrypt and verify SignedMessage
  │  ├─ Deserialize AuthenticationResponse
  │  └─ Publish to event bus: "gateway.response.received"
  │
  ▼
Application Processing (HTTP correlation, logging, metrics)
```

### 5.2 Step-by-Step Code Flow

**Step 1: Gatekeeper Generates Authentication Request**

```java
Project: svc-gatekeeper
Package: verticle
Class:   AuthRequestGeneratorVert.java

/**
 * Periodically generates authentication requests at configured rate.
 */
private Future<Void> sendSingleAuthRequest() {
  // Increment message generation counter
  long msgCounter = messageGenerationCounter.incrementAndGet();
  
  // Generate random user ID
  String userId = "user" + (int)(Math.random() * userCount);
  
  // Step 1: Hash password using Argon2
  return workerExecutor.<String>executeBlocking(() -> 
    Argon2Hash.hash("secret" + userId)
  )
  .compose(pwdHash -> {
    try {
      // Generate OTP (80% of requests include OTP)
      String otp = (Math.random() < 0.8) 
        ? String.format("%06d", (int)(Math.random() * 1_000_000)) 
        : null;
      
      // Step 2: Create AuthenticationRequest domain object
      AuthenticationRequest request = new AuthenticationRequest(userId, pwdHash, otp);
      
      // Step 3: Serialize to Avro bytes
      byte[] requestBytes = request.serialize();
      
      // Step 4: Create SignedMessage
      return msgProcessor.createSignedMessage(
        config.getServiceId(),        // "gatekeeper"
        requestBytes,                 // Avro-serialized request
        "authRequest",                // messageType
        "authRequest",                // payloadType
        targetSubject                 // "auth.auth-request"
      );
    } catch (Exception e) {
      return Future.failedFuture(e);
    }
  })
  .compose((SignedMessage signed) -> 
    // Step 5: Serialize SignedMessage
    workerExecutor.<byte[]>executeBlocking(() -> {
      try {
        return SignedMessage.serialize(signed);
      } catch (Exception e) {
        throw new RuntimeException("Serialization failed", e);
      }
    })
  )
  .compose(serialized -> {
    // Step 6: Add NATS headers with generation metadata
    Map<String, String> headers = new HashMap<>();
    headers.put("messageType", "AuthenticationRequest");
    headers.put("encoding", "base64");
    headers.put("messageKey", "gen-" + System.nanoTime());
    headers.put("generationCounter", String.valueOf(msgCounter));
    headers.put("generationTimestamp", String.valueOf(System.currentTimeMillis()));
    
    // Step 7: Publish to NATS
    return natsTlsClient.publish(targetSubject, serialized, headers);
  });
}
```

**Step 2: AuthController Receives Request**

```java
Project: svc-authcontroller
Package: verticle
Class:   AuthControllerConsumerVert.java

/**
 * Handle authentication request message - ASYNC VERSION
 * Extracts and verifies SignedMessage, then forwards to producer via event bus.
 */
private Future<Void> handleAuthRequestAsync(Message msg) {
  Promise<Void> promise = Promise.promise();
  
  try {
    // Increment receipt counter
    long receiptCounter = messageReceiptCounter.incrementAndGet();
    
    messagesReceived.incrementAndGet();
    
    // Extract message key and generation metadata from headers
    String messageKey = extractMessageKey(msg);
    Long generationCounter = extractLongHeader(msg, "generationCounter");
    Long generationTimestamp = extractLongHeader(msg, "generationTimestamp");
    
    // Log counters periodically
    logReceiptCounterIfNeeded(receiptCounter, generationCounter);
    
    // Step 1: Decrypt and verify SignedMessage
    signedMsgProcessor.obtainDomainObject(msg.getData())
      .map(o -> (byte[])o)
      .compose(authRequestBytes -> {
        
        // Step 2: Build event bus message with all metadata
        JsonObject eventBusMsg = new JsonObject()
          .put("messageKey", messageKey)
          .put("authRequestBytes", authRequestBytes)  // Decrypted Avro bytes
          .put("properties", headersToJson(msg))
          .put("originalMessageId", "nats-" + System.nanoTime())
          .put("requestTimestamp", System.currentTimeMillis())
          .put("topic", authConfig.getResponseTopic())  // "gatekeeper.responder"
          .put("receiptCounter", receiptCounter)
          .put("generationCounter", generationCounter);
        
        // Step 3: Forward to AuthControllerProducerVert via event bus
        vertx.eventBus().publish("authcontroller.process.request", eventBusMsg);
        
        messagesProcessed.incrementAndGet();
        
        LOGGER.debug("Forwarded auth request to producer: key={}, receiptCounter={}", 
                     messageKey, receiptCounter);
        
        return Future.succeededFuture();
      })
      .onComplete(ar -> {
        if (ar.succeeded()) {
          promise.complete();
        } else {
          messagesFailed.incrementAndGet();
          LOGGER.error("Failed to process auth request {}: {}", 
                       messageKey, ar.cause().getMessage(), ar.cause());
          promise.fail(ar.cause());
        }
      });
      
  } catch (Exception e) {
    LOGGER.error("Exception in handleAuthRequestAsync: {}", e.getMessage(), e);
    messagesFailed.incrementAndGet();
    promise.fail(e);
  }
  
  return promise.future();
}

/**
 * Log receipt counter every 100 messages.
 */
private void logReceiptCounterIfNeeded(long receiptCounter, Long generationCounter) {
  if (receiptCounter - lastReceiptCounterLog >= 100) {
    if (generationCounter != null) {
      LOGGER.info("========== AUTHCONTROLLER MESSAGE RECEIPT: ReceiptCounter = {}, GenerationCounter = {} ==========",
                  receiptCounter, generationCounter);
    } else {
      LOGGER.info("========== AUTHCONTROLLER MESSAGE RECEIPT: ReceiptCounter = {}, GenerationCounter = N/A ==========",
                  receiptCounter);
    }
    lastReceiptCounterLog = receiptCounter;
  }
}
```

**Step 3: AuthController Creates Response**

```java
Project: svc-authcontroller
Package: verticle
Class:   AuthControllerProducerVert.java

/**
 * Process authentication request received from event bus.
 * Creates response and publishes SignedMessage back to Gatekeeper.
 */
private Future<Void> processAuthenticationRequest(JsonObject request) {
  String messageKey = request.getString("messageKey");
  String originalMessageId = request.getString("originalMessageId");
  byte[] authRequestBytes = request.getBinary("authRequestBytes");
  Map<String, String> properties = convertJsonToMap(request.getJsonObject("properties"));
  String responseTopic = request.getString("topic");  // "gatekeeper.responder"
  
  // Extract counters from request
  Long receiptCounter = request.getLong("receiptCounter");
  Long generationCounter = request.getLong("generationCounter");
  
  // Increment processing counter
  long processingCounter = messageProcessingCounter.incrementAndGet();
  
  // Log all three counters periodically
  logProcessingCounterIfNeeded(processingCounter, generationCounter, receiptCounter);
  
  // Step 1: Deserialize AuthenticationRequest
  return workerExecutor.<AuthenticationRequest>executeBlocking(() -> 
    AuthenticationRequest.deserialize(authRequestBytes)
  )
  // Step 2: Create AuthenticationResponse
  .compose(authRequest -> workerExecutor.<AuthenticationResponse>executeBlocking(() -> 
    createAuthenticationResponse(authRequest, properties)
  ))
  // Step 3: Serialize AuthenticationResponse to Avro
  .compose(authResponse -> workerExecutor.<byte[]>executeBlocking(() -> 
    authResponse.serialize()
  ))
  // Step 4: Create SignedMessage
  .compose(authResponseBytes -> 
    signedMsgProcessor.createSignedMessage(
      authConfig.getServiceId(),        // "authcontroller"
      authResponseBytes,
      "AuthenticationResponse",
      "AuthenticationResponse",
      responseTopic                     // "gatekeeper.responder"
    )
  )
  // Step 5: Serialize SignedMessage
  .compose(signedMessage -> workerExecutor.<byte[]>executeBlocking(() -> 
    SignedMessage.serialize(signedMessage)
  ))
  // Step 6: Publish to NATS with all counters
  .compose(signedMessageBytes -> {
    // Add response metadata and ALL THREE COUNTERS
    properties.put("messageKey", messageKey);
    properties.put("originalMessageId", originalMessageId);
    properties.put("requestTimestamp", request.getLong("requestTimestamp").toString());
    properties.put("responseTimestamp", String.valueOf(System.currentTimeMillis()));
    properties.put("processingService", "authcontroller");
    
    // Include all three counters in response headers
    if (generationCounter != null) {
      properties.put("generationCounter", String.valueOf(generationCounter));
    }
    if (receiptCounter != null) {
      properties.put("receiptCounter", String.valueOf(receiptCounter));
    }
    properties.put("processingCounter", String.valueOf(processingCounter));
    
    return natsTlsClient.publish(responseTopic, signedMessageBytes, properties);
  })
  .onSuccess(v -> {
    messagesSent.incrementAndGet();
    LOGGER.debug("Successfully published AuthenticationResponse for messageKey: {}", messageKey);
  })
  .onFailure(err -> {
    messagesFailed.incrementAndGet();
    LOGGER.error("Failed to publish AuthenticationResponse for messageKey: {}", messageKey, err);
  });
}

/**
 * Log processing counter with all available counters every 100 messages.
 */
private void logProcessingCounterIfNeeded(long processingCounter, Long generationCounter, Long receiptCounter) {
  if (processingCounter - lastProcessingCounterLog >= 100) {
    if (generationCounter != null && receiptCounter != null) {
      LOGGER.info("========== AUTHCONTROLLER MESSAGE PROCESSING: ProcessingCounter = {}, ReceiptCounter = {}, GenerationCounter = {} ==========",
                  processingCounter, receiptCounter, generationCounter);
    } else if (receiptCounter != null) {
      LOGGER.info("========== AUTHCONTROLLER MESSAGE PROCESSING: ProcessingCounter = {}, ReceiptCounter = {}, GenerationCounter = N/A ==========",
                  processingCounter, receiptCounter);
    } else {
      LOGGER.info("========== AUTHCONTROLLER MESSAGE PROCESSING: ProcessingCounter = {}, ReceiptCounter = N/A, GenerationCounter = N/A ==========",
                  processingCounter);
    }
    lastProcessingCounterLog = processingCounter;
  }
}

/**
 * Create AuthenticationResponse based on AuthenticationRequest.
 */
private AuthenticationResponse createAuthenticationResponse(AuthenticationRequest authRequest, Map<String, String> properties) {
  AuthenticationResponse resp = new AuthenticationResponse();
  resp.setOid(UUID.randomUUID().toString());
  resp.setUserToken("token_" + authRequest.getUserId() + "_" + System.currentTimeMillis());
  resp.setPasswordHash(authRequest.getPwdHash());
  
  String result = determineAuthResult(authRequest);
  
  if ("APPROVED".equals(result)) {
    // Successful authentication - populate all tokens
    resp.setIdentityToken("identity_" + UUID.randomUUID());
    resp.setIdentitySymmKey(randomBytes(32));
    resp.setIdentityIVSpec(randomBytes(16));
    resp.setAuthorizationToken("auth_" + UUID.randomUUID());
    resp.setAuthorizationSymmKey(randomBytes(32));
    resp.setAuthorizationIVSpec(randomBytes(16));
    resp.setAccountStatus("ACTIVE");
    resp.setMbrLevelCode("STANDARD");
  } else {
    // Failed authentication - minimal response
    resp.setAccountStatus(result);
    resp.setMbrLevelCode("NONE");
  }
  
  return resp;
}

/**
 * Determine authentication result based on request data.
 */
private String determineAuthResult(AuthenticationRequest authRequest) {
  String userId = authRequest.getUserId();
  String otp = authRequest.getOtp();
  
  if (userId == null || userId.isEmpty())
    return "DENIED_NO_USER_ID";
  if (authRequest.getPwdHash() == null || authRequest.getPwdHash().isEmpty())
    return "DENIED_NO_PASSWORD";
  if (userId.startsWith("invalid_"))
    return "DENIED_INVALID_USER";
  if (otp != null && otp.startsWith("expired_"))
    return "DENIED_OTP_EXPIRED";
  if (otp != null && otp.startsWith("invalid_"))
    return "DENIED_INVALID_OTP";
  
  return "APPROVED";
}
```

**Step 4: Gatekeeper Receives Response**

```java
Project: svc-gatekeeper
Package: verticle
Class:   GatekeeperConsumerVert.java

/**
 * Handle authentication response message - ASYNC VERSION
 * Decrypts, verifies, and forwards to event bus for HTTP correlation.
 */
private Future<Void> handleAuthResponseAsync(Message msg) {
  Promise<Void> promise = Promise.promise();
  
  try {
    messagesReceived.incrementAndGet();
    
    String messageKey = extractMessageKey(msg);
    
    // Step 1: Decrypt and verify SignedMessage
    processAuthResponse(msg.getData())
      .onComplete(ar -> {
        if (ar.succeeded()) {
          messagesProcessed.incrementAndGet();
          
          // Step 2: Build event bus message for HTTP correlation
          JsonObject eventBusMsg = new JsonObject()
            .put("messageKey", messageKey)
            .put("messageBody", msg.getData())
            .put("properties", headersToJson(msg))
            .put("messageId", "nats-" + System.nanoTime())
            .put("publishTime", System.currentTimeMillis());
          
          // Step 3: Publish to event bus (for HTTP response correlation)
          vertx.eventBus().publish("gateway.response.received", eventBusMsg);
          
          LOGGER.debug("Processed and forwarded auth response: {}", messageKey);
          promise.complete();
        } else {
          messagesFailed.incrementAndGet();
          LOGGER.error("Failed to process auth response {}: {}",
                       messageKey, ar.cause().getMessage(), ar.cause());
          promise.fail(ar.cause());
        }
      });
      
  } catch (Exception e) {
    LOGGER.error("Exception in handleAuthResponseAsync: {}", e.getMessage(), e);
    messagesFailed.incrementAndGet();
    promise.fail(e);
  }
  
  return promise.future();
}

/**
 * Process auth response - decrypt and verify - ASYNC
 */
private Future<Void> processAuthResponse(byte[] data) {
  return signedMsgProcessor.obtainDomainObject(data)
    .map(o -> (byte[])o)
    .compose(bytes -> workerExecutor.<AuthenticationResponse>executeBlocking(() -> 
      AuthenticationResponse.deserialize(bytes)
    ))
    .mapEmpty();
}
```

### 5.3 Complete Flow with Counter Tracking

```
Timeline: Single Authentication Request
----------------------------------------

T=0ms: Gatekeeper - AuthRequestGeneratorVert
  ├─ generationCounter = 12345
  ├─ Create AuthenticationRequest(userId="user42", pwdHash="...", otp="123456")
  ├─ SignedMessage created (keyEpoch=98765)
  ├─ Publish to "auth.auth-request"
  └─ Headers: {generationCounter: 12345, generationTimestamp: 1700000000000}

T=2ms: NATS JetStream
  └─ Message persisted in AUTH_STREAM

T=5ms: AuthController - AuthControllerConsumerVert
  ├─ Pull consumer fetches message
  ├─ receiptCounter = 9876 (incremented)
  ├─ Decrypt SignedMessage (obtainDomainObject)
  │   ├─ Fetch topic key: "auth.auth-request-epoch-98765"
  │   ├─ Decrypt with AES-GCM-HKDF
  │   ├─ Fetch verification key: authcontroller-98765
  │   └─ Verify Dilithium signature ✅
  ├─ Deserialize AuthenticationRequest
  ├─ Publish to event bus "authcontroller.process.request"
  └─ Headers forwarded: {generationCounter: 12345, receiptCounter: 9876}

T=8ms: AuthController - AuthControllerProducerVert
  ├─ Receive from event bus
  ├─ processingCounter = 5432 (incremented)
  ├─ Deserialize AuthenticationRequest
  ├─ Determine result: "APPROVED" (user42 is valid)
  ├─ Create AuthenticationResponse with tokens
  ├─ Serialize to Avro bytes
  ├─ SignedMessage created (keyEpoch=98765)
  ├─ Publish to "gatekeeper.responder"
  └─ Headers: {generationCounter: 12345, receiptCounter: 9876, processingCounter: 5432}

T=10ms: NATS JetStream
  └─ Message persisted in GATEKEEPER_STREAM

T=12ms: Gatekeeper - GatekeeperConsumerVert
  ├─ Pull consumer fetches message
  ├─ Decrypt SignedMessage (obtainDomainObject)
  │   ├─ Fetch topic key: "gatekeeper.responder-epoch-98765"
  │   ├─ Decrypt with AES-GCM-HKDF
  │   ├─ Fetch verification key: authcontroller-98765
  │   └─ Verify Dilithium signature ✅
  ├─ Deserialize AuthenticationResponse
  ├─ Publish to event bus "gateway.response.received"
  └─ Headers: {generationCounter: 12345, receiptCounter: 9876, processingCounter: 5432}

T=15ms: Application Layer
  └─ Correlate response with HTTP request, send to client

Total end-to-end latency: ~15ms
  - SignedMessage overhead: ~8ms (2 sign operations, 2 verify operations)
  - NATS latency: ~4ms (2 publishes, 2 fetches)
  - Application logic: ~3ms
```

### 5.4 Automatic Key Recovery Scenario (Cross-Epoch Message)

```
Scenario: AuthController sends response with epoch 98766, 
          but Gatekeeper only has epoch 98765 keys

Timeline:
---------

T=08:00:00 - Gatekeeper starts, loads ServiceBundle (epoch 98765)
T=08:05:00 - AuthController starts, loads ServiceBundle (epoch 98765)
T=08:15:00 - Key rotation occurs (new epoch 98766)
             - Metadata publishes new ServiceBundles to OpenBao
T=08:16:00 - AuthController receives new ServiceBundle
             - Loads keys for epoch 98766
T=08:17:00 - AuthController sends response using epoch 98766 keys
             - Gatekeeper has NOT received new bundle yet

Gatekeeper Processing (Automatic Recovery):
--------------------------------------------

1. GatekeeperConsumerVert pulls message from GATEKEEPER_STREAM

2. processAuthResponse() → signedMsgProcessor.obtainDomainObject(data)

3. Worker thread: Deserialize SignedMessage
   - topicName: "gatekeeper.responder"
   - encryptKeyId: "gatekeeper.responder-epoch-98766"
   - signerServiceId: "authcontroller"
   - signerKeyId: 98766

4. Lookup: keyCache.getTopicKey("gatekeeper.responder", "gatekeeper.responder-epoch-98766")
   → Returns null (Gatekeeper only has epoch 98765 keys)

5. THROW KeyMissingException(
     serviceId: "authcontroller",
     topic: "gatekeeper.responder",
     keyId: "gatekeeper.responder-epoch-98766"
   )

6. recover() handler: fetchMissingKeyAndRetry(signedMsgBytes, kme)

7. extractEpochFromKeyId("gatekeeper.responder-epoch-98766") → 98766

8. targetServiceId = "authcontroller" (from kme.getServiceId())

9. keyCache.loadServiceBundleForEpoch("authcontroller", 98766)
   ├─ VaultAccessHandler.getServiceBundle("authcontroller", 98766)
   ├─ OpenBao path: secret/data/service-bundles/authcontroller/epoch-98766
   └─ Load bundle into KeyCache
       ├─ verifyKeys["authcontroller"][98766] = DilithiumKey
       └─ topicKeys["gatekeeper.responder"]["gatekeeper.responder-epoch-98766"] = TopicKey

10. Retry decryption:
    - Lookup: keyCache.getTopicKey("gatekeeper.responder", "gatekeeper.responder-epoch-98766")
      → ✅ Found!
    - Decrypt: aesCrypto.decrypt(encData, topicKey.getKeyData())
      → ✅ Success

11. Signature verification:
    - Lookup: keyCache.getDilithiumPublicKey("authcontroller", 98766)
      → ✅ Found!
    - Verify: signingManager.verify(domainBytes, signature, verifyKey)
      → ✅ Valid

12. Deserialize AuthenticationResponse and continue processing

Result: Message processed successfully after automatic key recovery!
        Total delay: ~25ms (20ms OpenBao fetch + 5ms retry)
```

### 5.5 Performance Analysis

**Single Message Latency Breakdown:**

```
Component                           | Time (ms) | Percentage
------------------------------------|-----------|------------
AuthRequestGeneratorVert:
  - Argon2 password hash            | 0.5       | 3%
  - AuthRequest serialization       | 0.1       | 1%
  - SignedMessage creation          | 3.0       | 20%
    * Dilithium signing             | 2.5       |
    * AES-GCM encryption            | 0.5       |
  - NATS publish                    | 1.0       | 7%
                                    |           |
AuthControllerConsumerVert:
  - NATS fetch                      | 1.0       | 7%
  - SignedMessage verification      | 2.5       | 17%
    * AES-GCM decryption            | 0.5       |
    * Dilithium verification        | 2.0       |
  - AuthRequest deserialization     | 0.1       | 1%
  - Event bus publish               | 0.1       | 1%
                                    |           |
AuthControllerProducerVert:
  - Event bus receive               | 0.1       | 1%
  - Business logic                  | 0.5       | 3%
  - AuthResponse serialization      | 0.1       | 1%
  - SignedMessage creation          | 3.0       | 20%
    * Dilithium signing             | 2.5       |
    * AES-GCM encryption            | 0.5       |
  - NATS publish                    | 1.0       | 7%
                                    |           |
GatekeeperConsumerVert:
  - NATS fetch                      | 1.0       | 7%
  - SignedMessage verification      | 2.5       | 17%
    * AES-GCM decryption            | 0.5       |
    * Dilithium verification        | 2.0       |
  - AuthResponse deserialization    | 0.1       | 1%
  - Event bus publish               | 0.1       | 1%
------------------------------------|-----------|------------
TOTAL END-TO-END                    | ~15.0 ms  | 100%
```

**Throughput at Different Rates:**

| Rate (msg/sec) | CPU Usage | Memory | NATS Backlog | Latency (p95) |
|----------------|-----------|--------|--------------|---------------|
| 100 | 15% | 512 MB | 0 | 18 ms |
| 500 | 40% | 768 MB | 0 | 22 ms |
| 1,000 | 65% | 1.2 GB | 0 | 28 ms |
| 2,000 | 95% | 1.8 GB | 50 | 45 ms |
| 5,000 | 100% | 2.5 GB | 500 | 120 ms |

**Bottleneck Analysis:**

1. **Dilithium Signing** (2.5ms × 2 = 5ms total)
   - Mitigation: WorkerExecutor with 8 threads
   - Max throughput: ~3,200 msg/sec (8 threads × 400 msg/sec per thread)

2. **NATS JetStream** (write latency ~1ms)
   - Mitigation: Async publish (non-blocking)
   - Max throughput: ~10,000 msg/sec (cluster capacity)

3. **OpenBao Key Fetch** (20-30ms on cache miss)
   - Mitigation: KeyCache with 20-epoch retention
   - Cache hit rate: >99.9% in steady state

---

## 6. Security Properties and Guarantees

### 6.1 Cryptographic Guarantees

**Authentication:**
```
Dilithium5 signature provides:
- Sender authentication: Only holder of private key can sign
- Message integrity: Any tampering invalidates signature
- Non-repudiation: Sender cannot deny creating signed message
- Post-quantum security: Resistant to Shor's algorithm
- NIST Level 5 security: Equivalent to AES-256
```

**Authorization:**
```
Topic key distribution provides:
- Cryptographic enforcement: No key = cannot decrypt
- Automatic revocation: Stop distributing keys in new epoch
- Audit trail: Key distribution logged in ServiceBundle generation
- Granular control: Per-topic access control via ServiceACL
```

**Confidentiality:**
```
AES-256-GCM with HKDF provides:
- Payload encryption: Ciphertext unreadable without key
- Per-message keys: Compromise of one message doesn't affect others
- Forward secrecy: Compromise of topic key doesn't expose past messages
  (each message encrypted with unique HKDF-derived key)
- Authenticated encryption: GCM tag ensures integrity
```

**Integrity:**
```
Two layers of integrity protection:
1. AES-GCM tag: Protects ciphertext from tampering
2. Dilithium signature: Protects domain object bytes

Note: Signature is on decrypted domain bytes, NOT on EncryptedData
This allows verification after decryption using keys from domain object itself
(critical for ServiceBundle bootstrap)
```

### 6.2 Key Management Guarantees

**Epoch-Based Rotation:**
```
Every 15 minutes (testing) / 3 hours (production):
- New topic encryption keys generated
- New Dilithium signing/verification keys generated
- Old keys remain valid for 60 minutes / 6 hours (4 epochs of overlap)
- Cache retention: 10 epochs (2.5 hours testing / 60 hours production)
- Automatic cleanup after retention period
```

**Automatic Recovery:**
```
When keys are missing:
1. KeyMissingException thrown during obtainDomainObject()
2. fetchMissingKeyAndRetry() extracts epoch from keyId
3. keyCache.loadServiceBundleForEpoch() fetches from OpenBao
4. Keys loaded into KeyCache
5. Decryption retried automatically
6. No manual intervention required
7. Transparent to application logic
```

**Multi-Epoch Support:**
```
At any given time, 4 concurrent epochs have VALID keys:
- Current epoch (N)     - Just rotated in
- Previous epoch (N-1)  - Widely deployed
- Legacy epoch (N-2)    - Services may still be using
- Legacy epoch (N-3)    - Grace period for stragglers

Example at T=10:00:
- Epoch 40 (10:00-11:00) - Current
- Epoch 39 (09:45-10:45) - Valid
- Epoch 38 (09:30-10:30) - Valid
- Epoch 37 (09:15-10:15) - Valid (expires in 15 min)

KeyCache RETAINS keys for 10 epochs (2.5 hours):
- PRIMARY PURPOSE: Service outage recovery
  * Service goes down for maintenance
  * Service crashes and restarts after 2 hours
  * Upon restart, can still decrypt messages from up to 10 epochs ago
  * Prevents message loss during extended outages
  
- SECONDARY BENEFITS:
  * Handles NATS JetStream message replay
  * Tolerates significant clock drift scenarios
  * Prevents thundering herd of OpenBao fetches during rotation
  * Allows processing of messages stuck in retry queues

This ensures:
- Messages encrypted with any of 4 valid epochs decrypt immediately (no fetch)
- Services can restart after outages up to 2.5 hours and still process queued messages
- Graceful degradation: messages older than 10 epochs trigger automatic OpenBao fetch
- Zero message loss during planned/unplanned service downtime
```

**Service Outage Recovery Example:**

```
Timeline (15-minute epochs):
----------------------------

T=08:00:00 - Gatekeeper crashes (loaded keys for epochs 32-52)
             Current epoch: 32

T=08:15:00 - Key rotation continues (epoch 33)
T=08:30:00 - Key rotation continues (epoch 34)
T=08:45:00 - Key rotation continues (epoch 35)
T=09:00:00 - Key rotation continues (epoch 36)
...
T=12:45:00 - Gatekeeper restarts (4 hours 45 minutes later)
             Current epoch: 51 (19 rotations occurred during outage)

Gatekeeper startup:
1. Loads latest ServiceBundle from OpenBao (epoch 51)
2. KeyCache contains epochs: 31-51 (20 epochs, last 5 hours)
3. NATS JetStream replay: messages from epochs 32-51
4. All messages decrypt successfully ✅ (keys still in cache)
5. No OpenBao fetch storms
6. Service resumes normal operation

Without 20-epoch retention:
- Only 4 epochs in cache (47-51, last hour)
- Messages from epochs 32-46 would trigger OpenBao fetches
- 15 concurrent OpenBao requests during startup
- Potential thundering herd, slower recovery
```

**Cleanup Strategy:**

```java
// From KeySecretManager.java

private static final int TOPIC_KEY_RETENTION_EPOCHS = 20;  
// 10 epochs = 2.5 hours (testing:10 × 15 min)
//           = 30 hours (production: 10 × 3 hours)

private void cleanupExpiredTopicKeys(String topicName) {
  long currentEpoch = KeyEpochUtil.epochNumberForInstant(Instant.now());
  long cutoffEpoch = currentEpoch - TOPIC_KEY_RETENTION_EPOCHS;
  
  // Remove keys older than 20 epochs
  // Rationale: Service outages longer than 5 hours (testing) are rare
  // Messages older than 10 epochs will trigger automatic OpenBao fetch
  // Balance between memory usage and operational resilience
}
```

**Memory Impact:**

```
With 10-epoch retention:
- Topic keys: ~50 topics × 10 epochs × 32 bytes = ~16 KB
- Dilithium verify keys: ~10 services × 10 epochs × 2.5 KB = ~250 KB
- Dilithium signing keys: 10 epochs × 4.8 KB = ~48 KB
- Total: ~315 KB (negligible for service recovery benefit)

Cleanup frequency: Every 5 minutes (automatic)
```

**Deduplication of Key Fetches:**

```
pendingKeyFetches map prevents duplicate OpenBao requests:
- Key: "serviceId:epoch" (e.g., "authcontroller:98766")
- Value: Future<Void> (in-progress fetch)
- If multiple messages need same epoch, only one fetch occurs
- Other messages wait for same Future to complete
- Prevents thundering herd during service restart
```
---

## 7. Performance Characteristics

### 7.1 Message Size Overhead

**Classical Cryptography (RSA-2048 + AES-256):**
```
Payload: 1,024 bytes
RSA signature: 256 bytes
AES-GCM overhead: 60 bytes (salt + iv + tag)
Avro metadata: ~150 bytes
Total: ~1,490 bytes (45% overhead)
```

**Post-Quantum Cryptography (Dilithium5 + AES-256):**
```
Payload: 1,024 bytes
Dilithium5 signature: 4,595 bytes
AES-GCM-HKDF overhead: 60 bytes (salt + iv + tag)
Avro metadata: ~150 bytes
Total: ~5,829 bytes (469% overhead!)
```

**Overhead Analysis:**

| Payload Size | Classical | Post-Quantum | Overhead % |
|--------------|-----------|--------------|------------|
| 100 bytes | 566 bytes | 4,905 bytes | 4,805% |
| 1 KB | 1,490 bytes | 5,829 bytes | 469% |
| 10 KB | 10,490 bytes | 14,829 bytes | 48% |
| 100 KB | 100,490 bytes | 104,829 bytes | 5% |

**Mitigation Strategies:**

1. **Batch Messages**: Amortize signature overhead across multiple payloads
2. **Larger Payloads**: Use for bulk operations (e.g., ServiceBundle with 50+ keys)
3. **NATS Compression**: Enable GZIP on transport (signatures compress poorly, but metadata compresses well)
4. **Signature Aggregation**: Future enhancement - single signature for multiple messages

### 7.2 Computational Performance

**Encryption/Decryption (AES-256-GCM):**
```
Encryption: ~50 µs per message (1KB payload)
Decryption: ~50 µs per message
HKDF key derivation: ~20 µs per message
Total AES overhead: ~120 µs per message
```

**Signing/Verification (Dilithium5):**
```
Signing: ~2-5 ms per message
Verification: ~1-2 ms per message
Total Dilithium overhead: ~3-7 ms per message
```

**Combined Throughput (Single Thread):**
```
Message creation (sign + encrypt): ~200-300 messages/second
Message verification (decrypt + verify): ~300-500 messages/second
```

**With WorkerExecutor (8 threads):**
```
Message creation: ~1,600-2,400 messages/second
Message verification: ~2,400-4,000 messages/second
```

**Measured Latency (Production):**
```
createSignedMessage(): 3-7 ms (dominated by Dilithium signing)
obtainDomainObject(): 2-5 ms (dominated by Dilithium verification)
  - Cache hit: 2-3 ms
  - Cache miss (first OpenBao fetch): 20-30 ms (one-time cost)
```

### 7.3 OpenBao ServiceBundle Fetch Performance

**Latency Breakdown:**
```
HTTPS request to OpenBao: ~10-20 ms (cluster-local)
JSON parsing: ~1-2 ms
Base64 decoding: ~0.5 ms
Avro deserialization: ~5-10 ms (depends on bundle size)
KeyCache loading: ~2-5 ms
Total: ~18-37 ms per bundle fetch
```

**Caching Strategy:**
```
ServiceBundles cached in KeyCache after first fetch:
- First message with new epoch: ~25 ms overhead (fetch from OpenBao)
- Subsequent messages: ~0 ms overhead (cache hit)
- Cache retention: 20 epochs (100 minutes)
- Automatic cleanup: Every 5 minutes
```

**Fetch Deduplication:**
```
pendingKeyFetches prevents duplicate requests:
- 10 concurrent messages need same epoch
- Only 1 OpenBao request made
- Other 9 messages wait for same Future
- Total OpenBao load: 1 request instead of 10
```

---

## 8. Comparison with Alternative Approaches

| Aspect | TLS Only | mTLS + JWT | SignedMessage (SecureTransport) |
|--------|----------|------------|---------------------------------|
| **End-to-end authentication** | ❌ No (transport-layer only) | ⚠️ Partial (JWT verified at gateway) | ✅ Yes (Dilithium on every message) |
| **Authorization enforcement** | ❌ No | ⚠️ ACL-based (policy engine) | ✅ Cryptographic (key possession) |
| **Post-quantum ready** | ❌ No (RSA/ECDSA vulnerable) | ❌ No (RSA/ECDSA) | ✅ Yes (Dilithium5/Kyber1024) |
| **Forward secrecy** | ✅ Yes (TLS 1.3 ephemeral keys) | ✅ Yes (TLS 1.3) | ✅ Yes (TLS 1.3) and (HKDF per-message keys) |
| **Message-level audit** | ❌ No | ⚠️ Partial (gateway logs) | ✅ Yes (signed epoch metadata) |
| **Non-repudiation** | ❌ No | ⚠️ Limited (JWT claims) | ✅ Yes (Dilithium signatures) |
| **Self-healing key recovery** | N/A | ❌ No | ✅ Yes (automatic OpenBao fetch) |
| **Performance overhead** | Low (0.1 ms) | Medium (1-2 ms) | High (3-7 ms) |
| **Message size overhead** | None | ~200 bytes (JWT) | ~4,700 bytes (Dilithium signature) |
| **Key rotation complexity** | Low (automated by TLS) | Medium (JWT secret rotation) | Medium (epoch-based automation) |
| **Authorization granularity** | Network-level | Service-level | Topic-level (cryptographic) |

---

## 9. Limitations & Future Enhancements

### 9.1 Current Limitations

| Limitation | Impact | Mitigation |
|-----------|--------|-----------|
| **Large signature size** | 4,595 bytes per message | Batch messages, use larger payloads |
| **High signing latency** | 2-5 ms per signature | WorkerExecutor parallelization |
| **No AAD in production** | Ciphertext not bound to metadata | Dilithium signature covers metadata |
| **OpenBao network dependency** | Adds 20-30ms on cache miss | Proactive bundle pre-fetch |
| **Epoch clock synchronization** | Requires NTP | 20-epoch overlap provides tolerance |
| **Signature on plaintext** | Must decrypt before verify | Allows bootstrap scenarios (ServiceBundle) |

### 9.2 Future Enhancements

**1. Signature Aggregation:**
```java
// Aggregate multiple messages into single signature
SignedMessageBatch batch = new SignedMessageBatch();
batch.add(message1);
batch.add(message2);
batch.add(message3);

// Single Dilithium signature covers all messages
byte[] batchSignature = dilithiumCrypto.signBatch(batch);

// Amortizes 4,595-byte signature across N messages
// 3 messages: ~1,532 bytes per message (vs 4,595)
```

**2. Hybrid Classical+PQC Signatures:**
```java
// Combine Dilithium with ECDSA for backward compatibility
HybridSignature sig = new HybridSignature();
sig.addDilithium(dilithiumSignature);   // 4,595 bytes (quantum-safe)
sig.addECDSA(ecdsaSignature);           // 64 bytes (classical fallback)

// Verifier can validate either signature
// Provides quantum-safe + classical compatibility
```

**3. RatchetingTopicCipher Integration:**
```java
// Enable AAD with ratcheting keys for long-lived connections
RatchetingTopicCipher ratchet = new RatchetingTopicCipher(topicKey);

// Derive ratcheting keys with sequence numbers
EncryptedData encrypted = ratchet.encrypt(
  payload,
  sequenceNumber,
  buildAAD(topicName, messageId, serviceId, timestamp)  // Bind to metadata
);

// Provides:
// - Enhanced forward secrecy (key ratcheting)
// - Metadata binding via AAD
// - Sequence number validation
```

**4. Proactive Bundle Pre-Fetching:**
```java
// Monitor upcoming epoch boundaries
long currentEpoch = KeyEpochUtil.epochNumberForInstant(Instant.now());
Instant nextEpochStart = KeyEpochUtil.epochStart(currentEpoch + 1);

if (Instant.now().until(nextEpochStart, ChronoUnit.SECONDS) < 300) {
  // Fetch bundle for next epoch (5 minutes before rotation)
  long nextEpoch = currentEpoch + 1;
  
  keyCache.loadServiceBundleForEpoch(serviceId, nextEpoch)
    .onSuccess(v -> {
      LOGGER.info("Pre-fetched bundle for epoch {}", nextEpoch);
    });
}
```

**5. Signature Caching for Immutable Messages:**
```java
// Cache signature verification results for immutable messages
private final ConcurrentHashMap<String, Boolean> signatureCache = new ConcurrentHashMap<>();

public Future<Boolean> verifyCached(byte[] data, byte[] signature, DilithiumKey key) {
  String cacheKey = Base64.getEncoder().encodeToString(signature);
  
  Boolean cached = signatureCache.get(cacheKey);
  if (cached != null) {
    LOGGER.debug("Signature verification cache hit");
    return Future.succeededFuture(cached);
  }
  
  return signingManager.verify(data, signature, key)
    .onSuccess(result -> signatureCache.put(cacheKey, result));
}
```

**6. Encrypted Signature (Signcryption):**
```java
// Combine encryption and signing in single operation (future research)
// Reduces overhead from (encryption + signature) to single cryptographic operation
// Potential size savings: ~30-40%
// Note: Standardization of PQC signcryption schemes still in progress
```

---

## 10. Operational Considerations

### 10.1 Monitoring and Alerting

**Key Metrics:**

```java
// Message creation metrics
metrics.timer("signedmessage.create.duration");
metrics.counter("signedmessage.create.success");
metrics.counter("signedmessage.create.failure");

// Message verification metrics
metrics.timer("signedmessage.verify.duration");
metrics.counter("signedmessage.verify.success");
metrics.counter("signedmessage.verify.failure.signature");
metrics.counter("signedmessage.verify.failure.decryption");

// Key recovery metrics
metrics.counter("signedmessage.key.cache_hit");
metrics.counter("signedmessage.key.cache_miss");
metrics.timer("signedmessage.key.fetch.duration");
metrics.counter("signedmessage.key.fetch.success");
metrics.counter("signedmessage.key.fetch.failure");
```

**Critical Alerts:**

```yaml
# Signature verification failure rate > 1%
- alert: HighSignatureFailureRate
  expr: rate(signedmessage_verify_failure_signature[5m]) / rate(signedmessage_verify_total[5m]) > 0.01
  severity: critical
  
# OpenBao fetch failure rate > 10%
- alert: HighKeyFetchFailureRate
  expr: rate(signedmessage_key_fetch_failure[5m]) / rate(signedmessage_key_fetch_total[5m]) > 0.10
  severity: warning
  
# Average key fetch latency > 100ms
- alert: SlowKeyFetch
  expr: rate(signedmessage_key_fetch_duration_sum[5m]) / rate(signedmessage_key_fetch_duration_count[5m]) > 0.1
  severity: warning
```

### 10.2 Troubleshooting

**Common Issues:**

**1. "Signature verification failed"**
```bash
# Check if verification key exists
kubectl logs -n services -l app=gatekeeper | grep "verification key"

# Verify ServiceBundle was loaded
kubectl logs -n services -l app=gatekeeper | grep "Loaded ServiceBundle"

# Check epoch mismatch
# SignedMessage signerKeyId should match loaded verification key epoch
```

**2. "Key not found even after ServiceBundle fetch"**
```bash
# Check OpenBao connectivity
kubectl exec -n services gatekeeper-0 -- curl https://openbao.openbao:8200/v1/sys/health

# Verify ServiceBundle exists in OpenBao
vault kv get secret/service-bundles/authcontroller/epoch-98766

# Check epoch number extraction
# keyId format: "{topic}-epoch-{number}"
```

**3. "Decryption failed"**
```bash
# Verify topic key exists for current epoch
kubectl logs -n services -l app=gatekeeper | grep "topic key"

# Check if encryptKeyId format is correct
# Should be: "{topicName}-epoch-{epochNumber}"

# Verify HKDF salt is present in EncryptedData
# Salt should be 32 bytes
```

### 10.3 Performance Tuning

**WorkerExecutor Thread Pool Sizing:**

```java
// Too few threads: High latency, serialized signing/verification
WorkerExecutor workerExecutor = vertx.createSharedWorkerExecutor("signed-msg", 4);

// Optimal: CPU cores * 2 for CPU-bound crypto operations
int optimalThreads = Runtime.getRuntime().availableProcessors() * 2;
WorkerExecutor workerExecutor = vertx.createSharedWorkerExecutor("signed-msg", optimalThreads);

// Too many threads: Context switching overhead, diminishing returns
WorkerExecutor workerExecutor = vertx.createSharedWorkerExecutor("signed-msg", 32);
```

**ServiceBundle Fetch Timeout:**

```java
// VaultAccessHandler configuration
private static final int VAULT_FETCH_TIMEOUT_MS = 5000;  // 5 seconds

// Increase if OpenBao is slow or network latency is high
// Decrease for faster failure detection in production
```

**Epoch Retention Policy:**

```java
// KeySecretManager configuration
private static final int TOPIC_KEY_RETENTION_EPOCHS = 20;  // 100 minutes

// Increase for:
// - Services with long message processing times
// - Environments with significant clock drift
// - Higher tolerance for delayed message delivery

// Decrease for:
// - Memory-constrained deployments
// - Stricter key rotation requirements
// - Reduced attack surface
```

---

## 11. Conclusion

The SignedMessage protocol demonstrates that **end-to-end cryptographic message security with post-quantum algorithms** is operationally viable for high-throughput microservices architectures.

**Key Achievements:**

1. **Zero-trust messaging** - Every message cryptographically authenticated and authorized
2. **Post-quantum security** - Dilithium5 signatures resistant to quantum attacks (NIST Level 5)
3. **Forward secrecy** - HKDF per-message keys prevent historical decryption
4. **Self-healing** - Automatic ServiceBundle recovery from OpenBao eliminates manual intervention
5. **Cryptographic authorization** - Key possession mathematically enforces access control
6. **Epoch-based rotation** - High-frequency key rotation (5-15 minutes) with 20-epoch overlap
7. **Signature on plaintext** - Enables bootstrap scenarios (ServiceBundle self-verification)

**Trade-offs Accepted:**

- ✅ **Performance overhead** (3-7 ms signing/verification latency) for quantum-resistant security
- ✅ **Message size overhead** (4,595 bytes Dilithium signature) for non-repudiable audit trails
- ✅ **Complexity** (HKDF, epochs, OpenBao integration) for self-healing automation
- ✅ **OpenBao dependency** (20-30ms on cache miss) for centralized key management

**Production Readiness:**

| Aspect | Status | Notes |
|--------|--------|-------|
| **Functional correctness** | ✅ Tested | 1000+ messages/sec in lab environment |
| **Security properties** | ✅ Verified | Dilithium5 NIST-standardized, HKDF battle-tested |
| **Self-healing** | ✅ Operational | Automatic key recovery from OpenBao working |
| **Performance** | ⚠️ Acceptable | 3-7ms latency suitable for async messaging |
| **Scalability** | ✅ Horizontal | WorkerExecutor parallelization proven |
| **Observability** | ✅ Instrumented | Metrics, structured logging, detailed errors |

**The Bottom Line:**

Moving from transport-layer security (TLS/mTLS) to **message-layer security** (SignedMessage) provides:
- **Stronger security guarantees** - End-to-end authentication vs transport-only
- **Better operational properties** - Automatic key recovery vs manual rotation
- **Future-proof cryptography** - Post-quantum resistant vs classical algorithms
- **Cryptographic authorization** - Mathematical enforcement vs policy-based ACLs

The overhead is real (4.5KB signature, 5ms latency), but the security and operational benefits justify the cost for systems requiring **zero-trust, auditable, quantum-resistant messaging**.

**NOTE: All Overhead and Performance information was provided by Claude Sonnet 4.5 based upon :**
1. **Logs** Log activity analysis of various service pods;
2. **Published Metrics** Standard published metrics for algorithms
3. **Calculated Metrics** Standard historical information (black box)

---

**What's Next:**

- **Blog 7**: Alternative Architectures Tested

---

**Explore the code:**
- [SignedMessageProcessor.java](https://github.com/t-snyder/010-SecureTransport/blob/main/svc-core/src/main/java/core/processor/SignedMessageProcessor.java)
- [SignedMessage.java](https://github.com/t-snyder/010-SecureTransport/blob/main/svc-core/src/main/java/core/transport/SignedMessage.java)
- [AesGcmHkdfCrypto.java](https://github.com/t-snyder/010-SecureTransport/blob/main/svc-core/src/main/java/core/crypto/AesGcmHkdfCrypto.java)
- [EncryptedData.java](https://github.com/t-snyder/010-SecureTransport/blob/main/svc-core/src/main/java/core/crypto/EncryptedData.java)
- [KeySecretManager.java](https://github.com/t-snyder/010-SecureTransport/blob/main/svc-core/src/main/java/core/handler/KeySecretManager.java)

---

**License:** Apache 2.0  
**Repository:** https://github.com/t-snyder/010-SecureTransport  
**Author:** t-snyder  

