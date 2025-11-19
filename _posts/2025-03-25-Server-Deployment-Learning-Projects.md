---
layout: single
title: "Server Deployment Learning Projects"
categories: [Kubernetes, Databases, Security]
tags: [cassandra, pulsar, etcd, encryption, minikube]
excerpt: "A collection of deployment prototypes exploring various server technologies including Apache Cassandra, Apache Pulsar, and Kubernetes etcd encryption in Minikube environments."
---

This series focuses on deploying and configuring various server technologies within Kubernetes/Minikube environments, with emphasis on security, connectivity, and operational best practices.

## Series Overview

### Security & Infrastructure

#### [Deploy-06: Encrypt Etcd Minikube]({% post_url 2024-12-01-Deploy-06-Encrypt-Etcd-Minikube %})
The purpose of the prototype is to provide a deployment of the Kubernetes Apiserver where the etcd store is encrypted.

**Key Technologies:** Kubernetes API Server, etcd encryption  
**Focus:** Securing Kubernetes cluster state with encryption at rest

**Why This Matters:** Etcd stores all Kubernetes secrets and configuration. This prototype demonstrates how to encrypt this critical data store, a requirement for production security.

---

### Messaging Systems

#### [Deploy-07: Apache Pulsar Connectivity]({% post_url 2025-02-27-Deploy-07-Apache-Pulsar-Connectivity %})
Deployment prototype exploring Apache Pulsar connectivity and messaging patterns within Kubernetes.

**Key Technologies:** Apache Pulsar, Kubernetes  
**Focus:** High-throughput distributed messaging systems

**Use Cases:** Event streaming, message queuing, pub-sub patterns for microservices

---

### Database Systems

#### [Deploy-08: Cassandra Minikube with External Connections]({% post_url 2025-03-17-Deploy-08-Cassandra %})
A set of deployable prototypes targeting Cassandra external connectivity deployed within a Minikube environment.

**Key Technologies:** Apache Cassandra, Kubernetes Gateway API, Cert-Manager, Istio Ambient Mode  
**Focus:** Stateful database deployments with external client access

**Deployment Features:**
- StatefulSet configurations for Cassandra clusters
- External connectivity via Gateway API
- TLS-secured client connections
- Certificate management with Cert-Manager

---

## Common Infrastructure

All projects are tested on:
- **Ubuntu:** 20.04.6 LTS
- **Minikube:** 1.34.0+
- **Kubernetes:** 1.31.0
- **Docker:** 27.2.0+

**Hardware Requirements:**
- **Processor:** Intel Core i7 or equivalent (8 cores recommended)
- **Memory:** 64 GB (minimum 32 GB for lighter deployments)

## Learning Path

1. **Start with Deploy-06** to understand Kubernetes security fundamentals
2. **Explore Deploy-07** for messaging architecture patterns
3. **Complete with Deploy-08** for stateful database deployments

## Repository Links

- [deploy-06-encrypt-etcd-minikube](https://github.com/t-snyder/deploy-06-encrypt-etcd-minikube)
- [deploy-07-apache-pulsar-connectivity](https://github.com/t-snyder/deploy-07-apache-pulsar-connectivity)
- [deploy-08-cassandra](https://github.com/t-snyder/deploy-08-cassandra)

## Notes

All deployment scripts are designed to be executed line-by-line in a terminal rather than as automated bash scripts. This approach allows for better understanding of each deployment step and easier troubleshooting.
