---
layout: readme
title: Secure Transport Research Project - Part 1 - Overview
exclude_from_feed: true
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
<img src="{{ '/assets/images/architecture-services.jpg' | relative_url }}" alt="SecureTransport Architecture - Services Overview showing Metadata Service, Watcher Service, and test harness components" width="500">

### 4.2 Deployment at a Glance
<img src="{{ '/assets/images/architecture-deployment.jpg' | relative_url }}" alt="SecureTransport Deployment Architecture across three Minikube clusters with NATS, OpenBao, and Istio components" width="500">

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

## 8. What This Blog Series Covers

- **Blog 1** (This Post): Architecture overview and problem space
- **Blog 2**: Step-by-step installation and deployment guide
- **Blog 3**: Service Permissions management - Static and Changeable
- **Blog 4**: Automated Certificate Rotation (Intermediate + Leaf) and certificate management
- **Blog 5**: OpenBao Integration and App Role token management
- **Blog 6**: NATS messaging with short-lived keys and topic permissions

---

## 9. Alternative Technologies Initially Tested
The main alternatives tested were Pulsar for messaging and a messaging push model versus a pull model.

### 9.1 Pulsar
Pulsar is a fairly heavy weight but very fast messaging server. It is made up of multiple components
- **Proxy Server** - Proxies client connections to various Brokers.
- **Broker Service** - Main messaging component
- **Bookie Service** - Persistence layer
- **Toolset** - Administration
- **Zookeeper** - Distributed configuration / leader election

While not all of these components need to be rotated with CA rotation, the Proxy and Broker service pods at a 
minimum must participate. Order is important, first the Brokers need to perform a
rolling restart, and then the Proxy pods. When the brokers restart the proxy connections to the brokers
are terminated, which terminates client connections to the Proxy. The proxy will try restarting and
eventually it will be successful as the broker pods come back online. 

- **Testing Experience** - It takes 1 - 3 minutes **(not seconds)** for the complete rotation to finalize. Given the frequency for the rotations we are seeking this was not acceptable.


### 9.1.1 Pulsar Architecture (Complex)
```
Producer/Consumer --> Proxy Layer (optional but beneficial)
                  --> Broker (stateful)
                      ├── BookKeeper (persistent storage)
                      ├── ZooKeeper (coordination)
                      └── Multiple connection types
                          ├── Client connections
                          ├── Proxy-to-broker
                          ├── Broker-to-broker
                          ├── Broker-to-BookKeeper
                          └── Broker-to-ZooKeeper
```

### 9.1.2. **Stateful Connection Model**

**Pulsar:**
- **Stateful broker connections** with:
  - Persistent subscription cursors
  - Message acknowledgment tracking
  - Partitioned topic routing state
  - Consumer group coordination
  - Backlog tracking per subscription

- CA rotation requires:
  - Draining in-flight messages
  - Persisting acknowledgment state
  - Coordinating reconnection across partitions
  - Handling consumer rebalancing
  - Managing backlog during transition

### 9.1.3 Partitioned Topic Complexity

**Pulsar:**
- Topics can have 100+ partitions
- Each partition = separate broker connection
- CA rotation requires:
  - Reconnecting to each partition broker
  - Coordinating across partition producers/consumers
  - Handling partial rotation failures
  - Managing message ordering across partitions during transition

**Example with 100 partitions:**
- 100 broker connections to update
- Each broker may be at different CA rotation stage
- Producer must track which brokers have rotated
- Risk of message duplication if partition ownership changes


## 9.2 Push vs. Pull Message Models: Complexity During CA Rotation
Push and pull messaging models represent fundamentally different approaches to message delivery, and these differences become particularly evident during critical infrastructure operations like Certificate Authority (CA) rotation.

### 9.2.1 Push Model

#### How It Works
In the push model, the message broker **actively sends** messages to consumers:
- The broker maintains connections to all subscribers
- Messages are delivered as soon as they arrive
- The broker tracks which consumers have received which messages
- Consumers are "pushed" data whether they're ready or not

#### Characteristics
- **Low latency**: Messages arrive immediately
- **Connection-oriented**: Broker maintains persistent connections to consumers
- **Broker controls flow**: The broker decides when to send messages

### 9.2.2 Pull Model

#### How It Works
In the pull model, consumers **request** messages from the broker:
- Consumers maintain connections to the broker
- Consumers fetch messages when they're ready
- The broker holds messages until requested
- Consumers control their own consumption rate

#### Characteristics
- **Consumer-controlled**: Consumers decide when to fetch messages
- **Natural backpressure**: Consumers only take what they can handle
- **Simpler broker logic**: Broker primarily stores and serves on request

### 9.3 Why Push Models Are More Complex During CA Rotation

#### 9.3.1 Connection Ownership and Lifecycle

**Push Model Problems:**
- The broker owns outbound connections to all consumers
- During CA rotation, the broker must:
  - Identify which connections use old certificates
  - Gracefully close existing connections
  - Re-establish connections with new certificates
  - Handle consumer unavailability during reconnection
  - Manage different certificate versions across consumers

**Pull Model Advantages:**
- Consumers own the connections
- Each consumer can independently:
  - Reload updated CA bundles on their own schedule
  - Close and reopen connections on their own schedule
  - Retry with new certificates without broker coordination
  - Handle their own failure scenarios

#### 9.3.2 State Management Complexity

**Push Model:**
```
Broker State:
├── Consumer A (cert v1, in-flight msgs: 5, ack pending: 3)
├── Consumer B (cert v2, in-flight msgs: 2, ack pending: 1)
├── Consumer C (cert v1, disconnected, buffered msgs: 100)
└── Consumer D (cert v2, connected, healthy)
```

The broker must track:
- Which certificate version each consumer is using
- In-flight messages per consumer
- Acknowledgment state per consumer
- Whether to allow connections with old certificates
- Grace periods for certificate migration

**Pull Model:**
```
Broker State:
├── Messages in queue
└── Accept connections with cert v1 OR cert v2
```

The broker only needs to:
- Store messages
- Accept connections from both old and new certificates (during rotation period)
- Serve messages when requested

#### 9.3.3 CA Bundle Management

**The CA Bundle Approach:**
During rotation, a CA bundle contains both the old and new CA certificates, allowing:
- Overlapping validity periods (rotation happens before expiry)
- Gradual rollout of new certificates
- No service disruption during the transition
- Time for all components to update

**Push Model Complexity:**
- Broker must manage CA bundle updates AND reconnection to all consumers
- Each consumer endpoint must have updated CA bundle before broker reconnects
- Broker must track which consumers have been updated
- Coordination required: "Has consumer X updated its CA bundle yet?"
- Failed reconnections require complex retry logic

**Pull Model Simplicity:**
- Broker updates its CA bundle to accept both old and new CAs
- Consumers update their CA bundles independently
- Existing connections continue to work
- New connections use whatever cert the consumer has (both work)
- No coordination needed between broker and consumers

#### 9.3.4 Failure Modes and Recovery

**Push Model Failure Scenarios:**
- **Partial rotation failure**: Some consumers rotated, some didn't
  - Broker must support both certificate versions simultaneously
  - Risk of message duplication during reconnection
  - Complex retry logic for failed deliveries
  
- **Connection storm**: All consumers disconnect/reconnect simultaneously
  - Broker must handle massive reconnection load
  - In-flight messages may be lost or duplicated
  - Acknowledgment state becomes uncertain

- **Consumer not reachable**: Consumer can't accept new certificate connection
  - Broker must decide: buffer, drop, or retry?
  - Memory pressure from buffered messages
  - Timeout and eviction policies become critical

**Pull Model Failure Scenarios:**
- **Consumer fails to rotate**: Uses old certificate
  - Broker rejects connection after grace period
  - Consumer retries with new certificate (consumer problem, not broker problem)
  - No message buffering needed

- **Connection storm**: All consumers reconnect
  - Stateless message serving scales naturally
  - No in-flight tracking means simpler recovery
  - Messages remain safely in queue

### 9.4 NATS-Specific Pull Considerations

#### NATS Core (Pull-like behavior via subscriptions):
```java
// Consumer manages its own connection
Connection nc = Nats.connect(options);
// During CA rotation:
// 1. Operator issues new CA (months before old CA expires)
// 2. CA bundle updated to include both old and new CA
// 3. Consumers reload CA bundle at their own pace
// 4. Consumers restart with new certs when convenient
// 5. Subscriptions automatically re-establish on reconnect
// 6. After rotation window, old CA removed from bundle
```

#### NATS JetStream (Pull consumers):
```java
// Explicit pull - consumer controls everything
PullSubscribeOptions pullOptions = PullSubscribeOptions.builder()
    .stream("mystream")
    .build();

JetStreamSubscription sub = js.subscribe("subject", pullOptions);

// During CA rotation:
sub.pull(10); // Consumer decides when to fetch
// Consumer updates CA bundle independently
// Connection management is entirely consumer-side
// Broker accepts both old and new certs via CA bundle
```

### 9.5 Coordination and Timing Windows

**Push Model:**
- Requires coordinated rotation across broker and all consumers
- Broker must know when consumers have updated CA bundles
- Need for complex grace periods and dual-certificate support
- Risk of split-brain scenarios
- Complex rollback procedures
- Tight coupling between broker and consumer update schedules

**Pull Model:**
- Rolling rotation possible with CA bundle
- Each consumer updates CA bundle independently
- Broker just needs CA bundle with both CAs
- Simple rollback (extend CA bundle overlap period)
- Loose coupling - no coordination needed
- Natural support for gradual rollout

### 9.6 Real-World Impact

### 9.6.1 Operational Complexity
- **Push**: Requires maintenance windows, coordination, monitoring dashboards for migration progress
- **Pull**: Can happen during business hours, self-healing, minimal monitoring needed

### 9.6.2 Failure Blast Radius
- **Push**: Broker failure affects all consumers simultaneously
- **Pull**: Consumer failures are isolated

### 9.6.3 Scalability
- **Push**: Complexity grows with O(n) consumers
- **Pull**: Complexity remains O(1) regardless of consumer count

## 9.6.4 Impact Conclusion

The push model's fundamental issue is that it **inverts the natural flow of responsibility**: the broker becomes responsible for managing the lifecycle and state of connections it doesn't fully control. During CA rotation, this creates a distributed systems problem where the broker must coordinate state across potentially thousands of independent consumers.

The pull model keeps responsibility at the edges: each consumer manages its own connection, certificate rotation, and failure recovery. The broker remains a simple, stateless message store that only needs to temporarily accept both old and new certificates during the rotation window.

For systems like NATS, this is why JetStream's pull consumers and core NATS's consumer-controlled subscriptions make CA rotation a non-event rather than a complex orchestration challenge.

**It should be noted that the pull model is essentially client driven server access. As such most servers which applications with significant technical foundations interact with use client driven access. Examples are data stores (postgres, cassandra, etc.) these are all client driven access.**


## 10 Conclusion

**Key Findings:**
- **Server requires Sighup capability - not restarts** - In order to achieve a few second CA rotation servers must be able to reread configuration and responde to changes without having to restart.
- **Client controls connections - not server** - In order to minimize rotation orchestration across multiple services the client needs to be in control of the connection and timing of requests.

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

