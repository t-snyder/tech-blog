---
layout: single
title: "Ingress and Kubernetes Gateway API Learning Projects"
categories: [Kubernetes, DevOps, Networking]
tags: [ingress, gateway-api, istio, cert-manager, nginx, vault]
excerpt: "A comprehensive series exploring Kubernetes ingress controllers, Gateway API implementations, and advanced certificate management with Cert-Manager, Vault, and Istio Ambient Mode."
---

This series of prototypes demonstrates the evolution from traditional Kubernetes Ingress to the new Gateway API, exploring various implementations and certificate management strategies in Minikube environments.

## Series Overview

The projects progress from basic ingress configurations to advanced Gateway API implementations with production-grade certificate management.

### Basic Ingress Projects

#### [Deploy-01: Basic Ingress (Ingress-Nginx, Cert-Manager, Pekko-Http)]({% post_url 2024-11-03-Deploy-01-Basic-Ingress %})
Prototype deploying basic ingress-nginx ingress with both http and https termination. Uses ingress-nginx, cert-manager, pekko-http.

**Key Technologies:** Ingress-Nginx, Cert-Manager, Pekko-Http  
**Focus:** HTTP and HTTPS termination at ingress controller

---

#### [Deploy-02: Advanced Ingress (Cert-Manager, Vault)]({% post_url 2024-11-07-Deploy-02-Advanced-Ingress %})
Project deploying ingress-nginx ingress with both http and https-passthrough; Cert-Manager and Hashicorp Vault CA.

**Key Technologies:** Ingress-Nginx, Cert-Manager, Vault CA  
**Focus:** Certificate lifecycle management with Vault as CA

---

### Gateway API Projects

#### [Deploy-03: Basic Gateway API (Istio - Ambient Mode, Cert-Manager)]({% post_url 2024-11-15-Deploy-03-Basic-Gateway-API %})
Shell instructions for deploying Kubernetes Gateway API, Istio Ambient Mode, and Cert-Manager using HTTPRoute for Http and Https-terminated, and TLSRoute for Passthrough.

**Key Technologies:** Kubernetes Gateway API, Istio Ambient Mode, Cert-Manager  
**Focus:** Introduction to Gateway API with Istio implementation

---

#### [Deploy-04: Nginx Gateway Fabric]({% post_url 2024-11-20-Deploy-04-Nginx-Gateway-Fabric %})
Project deploying Nginx Gateway Fabric as the Kubernetes Gateway API controller. Project purpose is to learn about the implementation functionality.

**Key Technologies:** Nginx Gateway Fabric, Gateway API  
**Focus:** Alternative Gateway API implementation comparison

---

#### [Deploy-05: Advanced Gateway API (Istio Ambient Mode, Cert-Manager, Vault)]({% post_url 2024-11-26-Deploy-05-Advanced-Gateway-API %})
A functional prototype using Kubernetes Gateway API supporting TLS Termination and Passthrough. Built using Istio (Ambient Mode), Cert-Manager and Hashicorp Vault for certificate lifecycle management and signing TLS certificates within a Minikube environment.

**Key Technologies:** Istio Ambient Mode, Cert-Manager, Vault, Gateway API  
**Focus:** Production-ready Gateway API with automated certificate management

---

#### [Thoughts and Conclusions from Ingress/Gateway API Learning Prototypes 1-5]({% post_url 2024-12-15-Thoughts-Conclusions-From-Prototypes(1-5) %})
Conclusions reached from implementing Ingress and Gateway API prototypes with Cert-Manager, Vault and Istio (Ambient Mode)

---

## Learning Path

1. **Start with Deploy-01** to understand basic ingress concepts
2. **Progress to Deploy-02** to learn certificate management with Vault
3. **Move to Deploy-03** to understand Gateway API fundamentals
4. **Explore Deploy-04** to compare different Gateway API implementations
5. **Complete with Deploy-05** for production-ready configurations

## Common Infrastructure

All projects are tested on:
- **Ubuntu:** 20.04.6 LTS
- **Minikube:** 1.34.0
- **Kubernetes:** 1.31.0
- **Docker:** 27.2.0

## Repository Links

Each project has its own GitHub repository with deployment scripts and documentation:
- [deploy-01-basic-ingress](https://github.com/t-snyder/deploy-01-basic-ingress)
- [deploy-02-advanced-ingress](https://github.com/t-snyder/deploy-02-advanced-ingress)
- [deploy-03-basic-gateway-api](https://github.com/t-snyder/deploy-03-basic-gateway-api)
- [deploy-04-nginx-gateway-fabric](https://github.com/t-snyder/deploy-04-nginx-gateway-fabric)
- [deploy-05-advanced-gateway-api](https://github.com/t-snyder/deploy-05-advanced-gateway-api)
