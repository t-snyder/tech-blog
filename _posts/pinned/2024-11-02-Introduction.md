---
layout: readme
excerpt: Introduction for Minikube based Ingress and Kubernetes Gateway API prototypes using Istio, Vault, and Cert-Manager
seo_title: Introduction for Minikube based Ingress and Kubernetes Gateway API prototypes using Istio, Vault, and Cert-Manager 
seo_description: An introduction explaining the implementation of prototypes built upon minikube kubernetes using ingress-nginx, istio in ambient mode, kubernetes gateway API, hashicorp vault, cert-manager and metallb.
pinned: true
---

# Various Prototypes exploring Kubernetes Ingress and Kubernetes Gateway API With Istio Ambient Mode, Cert-Manager and Hashicorp Vault

## Learning Prototypes Overview
Kubernetes, abbreviated as K8s, is a powerful open-source platform designed to
automate the deployment, scaling, and management of containerized applications. 
Originally designed and developed by Google, it was open sourced to the Linux 
Foundation in June 2014. By July 2014 IBM, Redhat, Microsoft, and Docker had 
joined the Kubernetes community.

Per Wikipedia, Kubernetes is one of the most widely deployed software
systems in the world. All major Cloud Providers (AWS, Azure, Google, Alibaba, IBM, Oracle, Digital
Ocean, etc. ) having Kubernetes based offerings. Currently the majority
of Cloud deployments are deployed using Kubernetes as the container
infrastructure. * CNCF Annual Survey 2022 (https://www.cncf.io/reports/cncf-annual-survey-2022/)**. CNCF.
January 31, 2023)

This adoption path and resulting experience has informed the ecosystem
as to what is working and what could work better, resulting in a rapidly
evolving and expanding platform.

This set of prototypes target 2 newer components of the Kubernetes
environment. The first is an evolutionary path from Ingress resources to
the Kubernetes Gateway API. The second is an evolution of the Istio
Service Mesh from sidecars to Ambient mode. As the prototypes become
more complex additional supporting deployments are included - Metallb
Load Balancer, Cert-Manager, and in a subsequent set of prototypes,
Hashicorp Vault.

## Prototype Purpose
The purpose of these prototypes is to provide a working deployment and
test environment for the new functionality (Kubernetes Gateway API and
Istio Ambient mode). The deployments are not production ready but
provide a basis for understanding how to use and deploy the
functionality.

The first step in this process is to understand the prior capabilities for Ingress
provided within the Kubernetes environment. These mainly rely on Ingress resources.
The first two Learning prototypes provide a foundation for understanding ingress
deployments using as a foundation ingress-nginx within minikube. These prototypes are:
  1. Learn-01-Basic-Ingress
  2. Learn-02-Advanced-Ingress

The next set of Prototypes switch to using Kubernetes Gateway API for cluster access.
These prototypes are:
  1. Learn-03-basic-gateway-api     (uses Istio Gateway)
  2. Learn-04-nginx-gateway-fabric  (uses Nginx Gateway Fabric)
  3. Learn-05-advanced-gateway-api  (uses Istio Gateway)

The 6th Prototype is on a separate technology track. It details how to encrypt etcd 
within the minikube environment.
  1. Learn-06-encrypt-etcd-minikube
    
## Evolution from Ingress to Kubernetes Gateway API
Per the Kubernetes Gateway API documentation - Gateway API is an
official Kubernetes project focused on L4 and L7 routing in Kubernetes.
This project represents the next generation of Kubernetes Ingress, Load
Balancing, and Service Mesh APIs. From the outset, it has been designed
to be generic, expressive, and role-oriented.
(https://gateway-api.sigs.k8s.io/)

The Gateway API is a relatively new API in the Kubernetes ecosystem that
provides a standardized way to manage ingress and egress traffic for
Kubernetes clusters. Kubernetes Gateway API (Gateway) is a set of APIs
implemented as Kubernetes Custom Resource Definitions that configure the
flow of traffic into and out of a Kubernetes cluster. It provides a
standardized way to define, configure, and manage gateways, which are
entry and exit points for traffic into and out of a cluster.

The main drivers for the new Gateway API were to overcome the
limitations encountered with Ingress resources as the scale and
complexity of Kubernetes deployments grew. Originally the goal of
Ingress was to provide a centralized way to manage external access to
services running inside a Kubernetes cluster, typically via HTTP/HTTPS
traffic at the L7 layer. It successfully met this goal with simple
traffic management use cases.

However, as Kubernetes deployments grew in complexity, several
limitations of the ingress resource became apparent:

- **Limited protocol support:** Ingress works only at Layer 7,
  specifically optimizing for HTTP and HTTPS traffic. Other L7 protocols
  (like gRPC) and non-L7 protocols (like TCP and UDP) must be handled
  using custom controller extensions rather than native Ingress
  capabilities.
- **Lack of Advanced Routing** Complex routing and traffic
  management scenarios required non-standard annotations. These include
  use cases like A/B testing, canary roll-outs, distributed tracing
  which require vendor specific annotations.

The Gateway API was designed to overcome these limitations and
provide a flexible and extensible framework by providing:

1.  **Multi-protocol support:** Gateway API supports multiple
    protocols, including HTTP(S), TCP, UDP, and gRPC. It provides
    support at both the L4 ( the Transport Layer - example protocols:
    TCP/UDP ) and L7( the Application Layer - example protocols: HTTP(s)
    / SIP ) layers.
2.  **Decoupling:** Gateway API decouples the gateway configuration
    from the underlying implementation, allowing for more flexibility
    and choice.
3.  **More configurability:** Gateway API provides a more
    comprehensive set of resources (Gateway, GatewayClass, Listener,
    Route, Filter) to manage complex traffic scenarios.
4.  **Standardization:** Gateway API aims to standardize the way
    gateways are managed across different Kubernetes distributions and
    environments. This decouples the gateway configuration from the
    underlying implementation.
5.  **Complex Routing and Traffic Management:** Gateway API provides for
    complex traffic management scenarios such as A/B testing, canary
    roll-outs. It also enables route customization based on arbitrary
    header fields as well as paths and hosts.

## Istio Service Mesh

Istio is one of the major open-source service mesh platforms that
provide a uniform way to manage and orchestrate microservices in a
distributed environment. Istio is generally deployed to support one or
more kubernetes clusters. (Per Wikipedia - Service Mesh)

An overview of Istio\'s key features and architectural components: (From
huggingface.io -- istio overview )

### Istio Key Features:
1.  **Service Discovery:** Istio provides a service registry that
    allows services to register themselves and be discovered by other
    services.
2.  **Traffic Management:** Istio enables traffic management
    features such as load balancing, circuit breaking, and request
    routing.
3.  **Security:** Istio provides mutual TLS encryption,
    authentication, and authorization for services.
4.  **Observability:** Istio collects metrics, logs, and tracing
    data for services, providing insights into performance and behavior.
5.  **Policy Enforcement:** Istio allows administrators to define
    and enforce policies for services, such as rate limiting and quotas.
6.  **Integration with Existing Tools:** Istio integrates with
    popular tools like Prometheus, Grafana, and Jaeger for monitoring
    and tracing.

### Istio Architecture - 2 Main Components:
1.  **Control Plane:** The control plane is responsible for managing
    the service mesh, including service discovery, traffic management,
    and policy enforcement.
2.  **Data Plane:** The data plane is responsible for forwarding
    traffic between services and enforcing policies. The historical data
    plane was an istio sidecar. The newer recent data plane addition is ambient
    mode.

Overall, Istio provides a robust and flexible way to manage and
orchestrate microservices in a distributed environment, providing
features like traffic management, security, and observability.

## Istio Ambient Mode

Istio Ambient Mode is a relatively new feature, and its capabilities and
limitations are subject to change as the project evolves but are fairly
stable with the 1.23 Istio release. In Ambient Mode, the Istio control
plane is not injected into each pod as a sidecar, unlike in the
traditional sidecar injection model. Instead, the control plane is
deployed as a separate entity, and the data plane is composed of
lightweight, ambient proxies that run as daemons on each node.

### Istio Ambient Mode Key characteristics:
1.  **No sidecar injection:** Unlike traditional Istio deployments,
    Ambient Mode does not require injecting the Istio control plane into
    each pod as a sidecar.
2.  **Lightweight ambient proxies:** Ambient proxies are small,
    lightweight, and run as daemons on each node. They are responsible
    for intercepting and routing traffic.
3.  **Centralized control plane:** The control plane is deployed
    separately and manages the ambient proxies.
4.  **No per-pod resource overhead:** Since there is no sidecar,
    there is no additional resource overhead (e.g., CPU, memory) per
    pod.

### Istio Ambient Mode Benefits:
1.  **Improved performance:** Reduced overhead and latency due to
    the absence of sidecars.
2.  **Simplified deployment:** Easier deployment and management, as
    the control plane is decoupled from the data plane.
3.  **Better scalability:** Ambient Mode can handle a larger number
    of services and pods more efficiently.

### Use cases:
1.  **Large-scale deployments:** Ambient Mode is suitable for
    large-scale deployments with thousands of services and pods.
2.  **Low-latency applications:** Applications requiring ultra-low
    latency might benefit from the reduced overhead of Ambient Mode.
3.  **Simplified service mesh:** Ambient Mode can be a good choice
    for organizations looking for a simplified service mesh solution
    with minimal overhead.

