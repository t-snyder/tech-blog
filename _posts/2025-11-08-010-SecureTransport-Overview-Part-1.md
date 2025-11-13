---
layout: readme
title: Secure Transport Research Project - Part 1 - Overview
pinned: false
excerpt: "A research prototype demonstrating automated Intermediate CA certificate rotation and high-frequency post-quantum key management in Kubernetes. Addresses the operational crisis of moving from yearly to hourly certificate rotation while implementing zero-trust architectures and PQC algorithms—validated under realistic message loads with zero-downtime guarantees."
categories: [Security, Cryptography, Kubernetes]
tags: [post-quantum, certificate-rotation, zero-trust, kubernetes, cert-manager, NATS, microservices, PKI]
series: "SecureTransport Research Prototype"
series_part: 1
---

# Overview: Hard Problems and Innovations in Secure Key & Certificate Rotation

## Introduction

SecureTransport is a research prototype demonstrating automated rotation of 
both leaf and Intermediate CA certificates and high-frequency encryption keys in a 
Kubernetes-native microservices architecture. Built on Vert.x 5.0, NATS messaging, and Cert-Manager, it addresses the operational challenges of transitioning from yearly to hourly/daily certificate rotation while implementing post-quantum cryptography (Kyber/Dilithium). The system achieves zero-downtime security updates through event-driven coordination, cryptographic authorization enforcement via signed ServiceBundles, and epoch-based key management with overlapping validity windows—validated continuously by high-throughput test services that prove correctness during rotation events.

### 1.1 The New Threat Reality
The internet security threat landscape is undergoing a fundamental transformation driven by converging forces: state-sponsored Advanced Persistent Threat (APT) groups now operate with nation-state resources and multi-year campaign timelines, while the impending arrival of cryptographically-relevant quantum computers threatens to break the RSA and elliptic curve cryptography protecting decades of encrypted data through "harvest now, decrypt later" attacks. Simultaneously, the attack surface has exploded—cloud-native architectures with ephemeral microservices, IoT device proliferation, and remote work infrastructure create millions of new vulnerability points, while AI-powered automated exploitation tools enable adversaries to discover and weaponize zero-days faster than defenders can patch. Certificate authorities and browser vendors are responding by mandating increasingly short certificate lifespans (from years to 90 days, with proposals for daily rotation), forcing organizations into an automation-or-die scenario where manual PKI management becomes operationally impossible. This perfect storm—sophisticated adversaries, quantum threats, massive attack surfaces, and compressed security lifecycles—demands not incremental improvements but fundamental architectural changes: cryptographic agility to swap algorithms on-demand, zero-trust models that verify continuously rather than authenticate once, and post-quantum cryptography deployed today to protect against tomorrow's quantum capabilities.

### 1.2 Industry Response

The cybersecurity industry is responding to these escalating threats with a fundamental reimagining of trust models and cryptographic infrastructure. Certificate authorities and browser vendors have aggressively shortened maximum certificate lifespans—Apple's Safari and Google Chrome now enforce 398-day maximums (down from multi-year certificates), with industry momentum pushing toward 90-day validity periods by 2027 and experimental deployments testing daily or even hourly rotation. In parallel, NIST finalized its post-quantum cryptography standards in 2024, selecting ML-KEM (Kyber) for key encapsulation and ML-DSA (Dilithium) for digital signatures, triggering a multi-year migration timeline where organizations must implement hybrid classical+PQC schemes while managing the operational burden of 5-38x larger cryptographic artifacts. Regulatory frameworks are codifying these changes—the EU's NIS2 Directive, CISA's post-quantum roadmap, and emerging financial services regulations all mandate cryptographic agility: the ability to swap encryption algorithms, key sizes, and certificate authorities without application rewrites or service disruptions.

Zero-trust architectures represent perhaps the most profound shift, abandoning the perimeter-based "castle and moat" security model that dominated for decades. Traditional networks assumed anything inside the firewall could be trusted—authenticate once at the VPN gateway, then freely access internal resources. Zero-trust inverts this: "never trust, always verify" means every request, every microservice call, every data access requires fresh cryptographic proof of identity and authorization, regardless of network location. In practice, this demands continuous authentication (short-lived credentials that expire in minutes or hours, not days), microsegmentation (cryptographically enforced boundaries between every service), and policy-based access control where permissions are cryptographically bound to identity tokens rather than network addresses or firewall rules. For certificate-based systems, zero-trust means frequent rotation isn't just a security improvement—it's a functional requirement, since long-lived certificates create windows where compromised credentials remain valid. This architectural shift, combined with PQC migration and compressed certificate lifespans, creates the operational crisis SecureTransport addresses: how do you rotate certificates and keys hundreds of times more frequently than before, across distributed microservices, with zero downtime and cryptographic proof of correctness?

**The Bottom Line:** The security practices that worked for the last decade won't protect us in the next one.

### 1.2 The Hard Problems Nobody Talks About

Moving to short-lived certificates and post-quantum encryption sounds simple in theory. In practice, it creates a cascade of brutal operational challenges:

#### **Problem 1: Automation at Scale - Or Die Trying**

**The Challenge:** Moving from yearly to 90-day certificates means 4x more renewals; daily rotation is 365x more operations; hourly rotation exceeds 1000x. Manual processes that worked before now guarantee outages, yet coordination across dozens of microservices with zero downtime tolerance makes automation non-trivial.

**SecureTransport's Approach:** Cert-Manager automates leaf issuance while the Metadata service generates Intermediate CA bundles with epoch-based rotation (20-minute cycles, 80-minute validity). The Watcher service coordinates NATS certificate updates via pod reconfiguration (SIGHUP, not restart). Topic encryption keys rotate every 15 minutes with 1-hour validity, orchestrated through event-driven architecture.

---

#### **Problem 2: Post-Quantum Cryptography Overhead**

**The Challenge:** Kyber public keys are 5.3x larger than RSA-2048; Dilithium signatures are 37.8x larger than ECDSA. This compounds across thousands of messages per second, increasing bandwidth consumption, storage requirements, and latency—network infrastructure designed for classical cryptography faces unexpected bottlenecks.

**SecureTransport's Approach:** Vert.x 5.0's reactive architecture prevents thread blocking from PQC operations. NATS provides efficient transport, Avro serialization minimizes message overhead, and Caffeine caching reduces repeated cryptographic operations. The system was designed for PQC from day one, not retrofitted.

---

#### **Problem 3: PKI Infrastructure Strain**

**The Challenge:** Certificate Authorities face 4-365x increased issuance volume while OCSP/CRL systems must scale proportionally. Certificate Transparency logs grow unsustainably, monitoring systems drown in alerts, and storage costs multiply with larger PQC certificate chains—all while CA rate limiting can cause production outages.

**SecureTransport's Approach:** The Metadata service generates Intermediate CA bundles using OpenBao PKI, reducing external CA dependencies. The Watcher coordinates NATS certificate rotation without pod restarts. Local certificate caching and pre-renewal before expiration windows minimize CA load spikes.

---

#### **Problem 4: Key Management at High Frequency**

**The Challenge:** Short-lived keys (hours, not years) require constant cryptographically-secure generation and gap-free distribution across microservices. Clock drift causes "key not valid yet" errors, race conditions emerge during rotation windows, and every rotation cycle creates failure opportunities.

**SecureTransport's Approach:** Every SignedMessage includes topic keyId, epoch, signing keyId, and service identifier—authorized services can fetch missing keys on-demand. Overlapping validity windows (15-minute rotation, 1-hour expiry) maintain multiple concurrent valid keys. 100-minute retention windows handle clock drift, with automatic epoch calculation and NATS-based synchronization backed by OpenBao storage.

```java
TopicKey {
  keyId:       "auth.request-epoch-1234567890"
  epochNumber: 1234567890
  createdTime: 2025-11-08T06:00:00Z
  expiryTime:  2025-11-08T12:00:00Z  // Overlapping validity
  role:        "current"  // current, next, or legacy
}
```
---

#### **Problem 5: Authorization in a Rotating World**

**The Challenge:** Traditional RBAC assumes static credentials, but frequent key rotation breaks permission caching. Authorization decisions must account for key epochs while revocation must be immediate. Audit trails explode with rotation events, and managing HTTPS service graphs with short-lived credentials doesn't scale.

**SecureTransport's Approach:** Cryptographic authorization enforcement—if you don't have the topic key, you can't decrypt the message. Keys are bundled with permissions in signed ServiceBundles, making authorization decisions at distribution time rather than message time. Revocation is automatic: revoked services simply don't receive new epoch keys.

```java
TopicPermission {
  topicName:         "auth.request"
  producePermission: true
  consumePermission: false
  topicKeys:         { keyId -> TopicKey }  // Only if authorized
}
```
---

## 2. What is SecureTransport?

**A research prototype** exploring practical solutions to the operational challenges of:

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

## 3 Core Functionality - A Short Preview

### 3.1 Core Security Processes Supported (A Preview)
**1. Intermediate CA Bundle Rotation**
- Overlapping Intermediate Certificates and Root Certificate Bundle on epoch boundaries and published to all authorized services.
- The Metadata service generates and publishes new CA bundles with the help of OpenBao PKI.
- The Watcher service coordinates NATS/transport certificate updates when new CA material is present.
- Other services receive the Ca bundle updates and process new connections, producers and consumers.

**2. Automated Service Matrix - Service Bundle Authorization**
- Metadata service auto-generates an authorization matrix (which service can access what, and with what permissions) and handles key generation/distribution accordingly.
- Topic permission mappings are distributed with cryptographic keys in the ServiceBundle.
- Every SignedMessage couples authentication (Dilithium signature), authorization (topic key), and rotation context (epoch reference)—ensuring only authorized, authenticated messages are accepted.
- Key/cert epoch transitions are monitored, enforced, and cryptographically provable.

**3. Short-Lived, Automated Generation and Rotation of Encryption and Signing Keys**
- Encryption and Signing keys are created within the Metadata service using the authoization matrix in 2 above.
- Transport and topic encryption keys rotate as frequently as sub hourly to multi-hour or daily.
- Overlapping valid keys are managed via epochs for smooth rollovers.

**4. OpenBao AppRole Access**
- OpenBao uses AppRole access which support cross cluster access.
- Requires strict explicit path capabilities authorization.
- Each service periodically updates their token and secret key with OpenBao

#### Distinctives
- Focus on automating intermediate CA rotation, not just standard leaf certs.
- PQC support (Kyber/Dilithium) for post-quantum readiness.
- Cryptographic authorization, not just authentication.
- Zero-touch, event-driven update architecture.

### 3.2 The Components Which Make this Work

Three innovations that make this work:

#### 3.2.1 The ServiceBundle

A cryptographically-signed package containing everything a service needs:
- **Signing keys** for message authentication (Dilithium)
- **Verification keys** for validating other services
- **Topic encryption keys** with embedded permissions (AES-256)
- **Authorization matrix** defining service-to-service communication

```java
public class ServiceBundle {
  Map<Long, DilithiumKey> signingKeys;
  Map<String, Map<Long, DilithiumKey>> verifyKeys;
  Map<String, Map<String, TopicKey>> topicKeys; // {topic -> {keyId -> TopicKey}}
  Map<String, TopicPermission> topicPermissions;
  // ... cryptographic signatures included
}
```

*Detailed in Blog 3*

### 3.2.2 The SignedMessage

Every message carries cryptographic proof of authenticity and authorization:
- **Dilithium signature** proving sender identity
- **Epoch-based key references** for validation
- **Encrypted payload** using topic-specific keys with HKDF
- **CA epoch tracking** for certificate validation

```java
SignedMessage message = new SignedMessage(
    ...,
    dilithiumSignature, // authentication
    topicKey.keyId,     // authorization (can this service access this topic?)
    keyEpoch,           // rotation context
    caEpoch             // cert trust context
);
```

*Detailed in Blog 3*

### 3.2.3 Automated Authorization Matrix

The **Metadata service** provides a configurable and updateable services ACL which is used to generate and maintain:
- Which services can communicate with which
- Topic-level produce/consume permissions
- Key distribution based on authorization
- Dynamic updates as services are added/removed

**How Permissions Are Enforced:**
- Only services with both the right signature and the current topic key can produce/consume certain topics
- Permissions are checked cryptographically—no static ACLs or central bottleneck

*Detailed in Blog 4*

readme
## 4. High-Level Architecture
### 4.1 The System at a Glance
<img src="/assets/images/architecture-services.jpg" alt="Alt text" width="500">

### 4.2 Deployment at a Glance
<img src="/assets/images/architecture-deployment.jpg" alt="Alt text" width="500">

### 4.3 Core Services and Responsibilities

#### Metadata Service (The Authority)

    Maintains authorization matrix defining service-to-service communication
    Generates and signs ServiceBundles for all services defining and implementing service permissions.
    Creates topic encryption keys with embedded permissions
    Publishes Intermediate CA certificate bundles
    The brain of the security infrastructure
    Detailed in Blog 3 & 4

#### Watcher Service (The NATS Coordinator)

    Monitors certificate and secret changes via Kubernetes watches
    Orchestrates NATS certificate rotation across the cluster
    Triggers NATS pod updates when CA bundles change
    Ensures zero-downtime during certificate rotation
    The orchestrator of rotation events
    Detailed in Blog 4

#### Service Core (The Foundation)

    Shared library providing cryptographic operations
    ServiceBundle parsing and validation
    SignedMessage creation and verification
    NATS TLS client with automatic certificate reloading
    Common utilities used by all services
    The toolkit every service depends on
    Detailed in Blog 3

### 4.4 Test/Demonstration Services

To validate the system under realistic load and prove correctness during rotation events, the prototype includes two test harness services:

#### Gatekeeper Service (Load Generator)

    Generates high-volume authentication requests - configurable
    Publishes messages to auth.request topic
    Consumes responses from auth.response topic
    Tracks message counters, latency, and errors
    Purpose: Simulate client applications generating traffic
    Configuration in Blog 2

#### AuthController (Processing Simulator)

    Consumes authentication requests from auth.request topic
    Processes messages and generates authentication responses
    Publishes responses to auth.response topic
    Tracks processing counters and success/failure rates
    Purpose: Simulate backend services processing requests

#### Why These Services Matter:

From the code comments in AuthControllerServiceMain.java:

    "The two services' purpose is to provide a testbed for testing the functionality and resiliency of the encryption and signing key rotation as well as the [NATS] ca certificate bundle rotation."

These services create a realistic message flow that allows validation of:

    ✅ Message integrity during key rotation (15-minute cycles)
    ✅ Zero message loss during CA certificate rotation
    ✅ Signature verification across epoch boundaries
    ✅ Performance impact of PQC operations under load
    ✅ Service resilience when keys/certificates change

Critical Insight: These aren't just "demo apps" - they're stress testing infrastructure that proves the core innovation (CA rotation + key rotation) works under real-world conditions.


### 4.5 Technology Choices

Each technology was selected to solve a specific hard problem:

  **Vert.x 5.0 -** Reactive, non-blocking architecture essential for handling PQC overhead (37.8x larger signatures) without thread blocking

  **NATS -** High-performance messaging with native mTLS, low latency, and support for dynamic certificate reloading

  **Cert-Manager -** Industry-standard Kubernetes certificate automation; handles leaf certificate issuance and renewal (6-hour duration, 3-hour renewal)

  **OpenBao -** FIPS-compliant secrets management (HashiCorp Vault open-source fork); provides secure token distribution via sidecar agents

  **Istio in Ambient Mode -** A service mesh currently only provides mTLS between pods in a cluster
  
  **Fabric8 -** Native Kubernetes resource watching in Java; powers svc-watcher's certificate change detection

  **BouncyCastle FIPS -** Proven cryptographic library with post-quantum algorithm support (Kyber, Dilithium)

  **Avro -** Compact binary serialization reduces message size overhead (critical when PQC already increases payload by 5-38x)


## 5. Design Philosophy: Built for Reality

- **Principle 1: Event-Driven**

    Services react to certificate/key changes via NATS events
    Immediate propagation of security updates across the cluster

- **Principle 2: Cryptographic Enforcement, Not Policy**

    Authorization tied to key possession, not ACL checks
    No centralized permission service bottleneck
    If you don't have the topic key, you can't decrypt the message - mathematically enforced

- **Principle 3: Graceful Degradation**

    Overlapping key validity prevents gaps (1-hour expiry, 15-minute rotation = 4 concurrent valid keys)
    Multi epoch retention window handles clock drift
    Automatic fallback to previous epochs on validation errors

- **Principle 4: Zero-Trust Messaging**

    Every message carries cryptographic proof (Dilithium signature)
    No implicit trust between services
    Continuous verification, not "authenticate once"
    Receiver must have access to both encryption key (with hkdf info) and signing public key
    With AES-GCM-256 HKDF and key rotation every 15 minutes - the blast radius is dramatically reduced

- **Principle 5: Operational Automation**

    No manual certificate management
    Self-healing rotation processes
    Observable state transitions via logs and metrics
    Test harness (gatekeeper ↔ authController) validates every rotation

- **Principle 6: No Service Downtime for Rotations**

    Services should not require downtime / restarts for Certificate or Key rotations
    Message processing interruptions should be a few seconds only for the TLS reconnection, and consumer rotation
    Rotations should manage retries until successful with expanding wait times
    
- **Principle 7: Test What You Fly**

    Realistic message loads during development
    Continuous validation of rotation correctness
    Performance metrics under PQC overhead
    Early detection of race conditions and edge cases


---

## 6. Why This Architecture?

**Design Decisions Driven by Real Problems:**

| Hard Problem | Traditional Approach | SecureTransport Solution |
|-------------|---------------------|-------------------------|
| **Automation Scale** | Scripts + hope | Event-driven rotation with Watcher Service |
| **Service Downtime** | Acceptable | None |
| **Messaging Downtime** | Acceptable to pod restart | Goal - 1 to 5 seconds |
| **PQC Overhead** | Accept performance hit | Reactive architecture + caching |
| **Key Distribution** | Push to all services | Pull-based ServiceBundle model, pull backup |
| **Clock Drift** | Tight time windows | Multi epoch retention, overlapping validity |
| **Authorization** | Policy-based checks | Cryptographic enforcement via key distribution |
| **CA Load** | Direct CA queries | Cert-Manager buffering + local caching |
| **Monitoring** | Manual certificate checks | Proactive expiration detection |
| **Rollback** | Manual intervention | Epoch-based automatic fallback |

---

## 7. Current Limitations (Its Still a Prototype)

- **Service Restarts** - The current implementation is script deployment driven. Service pods which restart after keys and ca bundles have been updated will not start successfully.
- **Service Core** - The functionality within the service core and especially the verticles which is supports need to be abstracted into a Service Core class which an end service can extend for its own functionality.
- **Test Cases** - The true test cases are the Gatekeeper and AuthController services.
- **Service Identity** - Needs significant improvement, currently just a string Id.

---

## 7. What This Blog Series Covers

- **Blog 1** (This Post): Architecture overview and problem space
- **Blog 2**: Step-by-step installation and deployment guide
- **Blog 3**: Service Permissions management - Static and Changeable
- **Blog 4**: KeyExchange with ServiceBundle
- **Blog 5**: Automated CA rotation (Intermediate + Leaf) and certificate management
- **Blog 6**: OpenBao integration and App Role token management
- **Blog 7**: NATS messaging with short-lived keys and topic permissions
- **Blog 8**: SignedMessage deep dive

---

## 8. Conclusion

**Key Takeaways:**
- This is a **research prototype** exploring solutions to real operational challenges
- **Main innovation**: Automated **Intermediate CA certificate rotation**, not just leaf certificates
- Addresses the hard problems of short-lived certificates and post-quantum cryptography
- Event-driven, zero-downtime approach to security automation
- Built for the emerging requirements of quantum-safe cryptography

**The security industry is moving to:**
- ✅ Short-lived certificates (90 days → hourly/daily)
- ✅ Post-quantum cryptography (Kyber, Dilithium)
- ✅ Zero-trust architectures
- ✅ Cryptographic agility

**SecureTransport bridges that gap** - a working prototype, today.

---

**Explore the code:** [010-SecureTransport on GitHub](https://github.com/t-snyder/010-SecureTransport)

**Next Steps:**
- Follow this blog series to understand each component in depth
- Try the installation guide in Blog 2
- Contribute feedback and insights from your own experiences

---

*Ready to get started? Proceed to Blog 2: Installation and Deployment Guide!*

---

**License:** Apache 2.0  
**Repository:** https://github.com/t-snyder/010-SecureTransport

