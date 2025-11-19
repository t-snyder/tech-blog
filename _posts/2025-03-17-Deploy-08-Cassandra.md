---
layout: readme
title: Deploy-08 Cassandra Minikube with External Connections (Kube Gateway API, Cert-Manager, Istio Ambient Mode)
exclude_from_feed: true
pinned: false
excerpt: A set of deployable prototypes targeting Cassandra external connectivity deployed within a Minikube environment.
---
Github Project: [https://github.com/t-snyder/deploy-08-cassandra](https://github.com/t-snyder/deploy-08-cassandra)

## 1 - Project Purpose
The purpose of this Learning set of deployment prototypes is to be able to deploy Cassandra
clusters into Kubernetes minikube for development and testing purposes. The deployments
use kubernetes yaml manifest files for each deployment, and a script (deploy.sh) to manually process the
the deployment. 

## 2 - Project Dependencies

| Core Infrastructure | Version         |
| --------------- | --------------- |
| Minikube        | 1.34.0          |
| Kubernetes      | 1.31.0          |
| Docker          | 27.2.0          |

### 2.1 Computer Configuration:

| Name            | Description                             |
| --------------- | --------------------------------------- |
| Ubuntu          | 20.04.6 LTS                             |
| Processor       | Intel® Core™ i7-7700K CPU @ 4.20GHz × 8 |
| Memory          | 64 GB                                   |

### 2.2 Deploying the Core Infrastructure Dependencies
Instructions for deploying the Core Infrastructure Dependencies listed above are NOT included within this set
of Prototypes as there are numerous targeted deployment instructions for each better suited for your
particular OS.

## 2.3 Dependencies Deployed within the Prototype Scripts ( As Required )

| Deployed Name          | Version |
| ---------------------- | ------- |
| Cert-manager           | 1.15.5  |
| Istio                  | 1.23.2  |
| Kubernetes Gateway API | 1.2.0   |
| Metallb                | 0.9.6   |

## 2.4 Dependency Documentation Referenced
   1. Cassandra Kubernetes Manifests - https://kubernetes.io/docs/tutorials/stateful-application/cassandra/
   2. Kubernetes Gateway API         - https://gateway-api.sigs.k8s.io/guides/
   3. Cert-Manager                   - https://cert-manager.io/docs/
   4. Istio Ambient Mode             - https://istio.io/latest/docs/ambient/
   5. Apache Cassandra               - https://cassandra.apache.org/doc/latest/
   

## 3 Prototype Script Functionality
### 3.1 Important Notes
**Note :**<br>
  1. *The commands within the shell files below are meant to be copy pasted (one or a few lines at a time) into a terminal, and not run as an automated bash script.*
  2. *Each script shell contains a PROTODIR env. You need to update this for your directory paths.*

### 3.2 The Simple Java Clients Provided
The project repository includes 2 java cassandra test clients within the "proto-cass" eclipse
project. One for unencrypted client access (learn.CassandraProto.java) and one for tls encrypted client access (learn.CassandraTLS.java).
The paths hardcoded in each need to be updated for where you have deployed the project.

## 4 The Deployment Prototypes
### 4.1 Deployment-01 (Kubernetes example Cassandra deployment)
This deployment consisting of a service and a statefulset was obtained from the kubernetes 
tutorials - ***https://kubernetes.io/docs/tutorials/stateful-application/cassandra/***

With the exception of removing some probes the manifests are the same.

Its purpose is to provide a baseline for further changes and additions within the subsequent
deployment prototypes. It should be noted that the java clients will not have access to this
deployment as the service is not configured as a LoadBalancer.

The deployment script ***deploy.sh*** within the scripts folder performs the following:
   1. Deploys a fresh minikube with minikube addons (dashboard);
   2. Creates the cassandra namespace
   3. Deploys the service and the the statefulset with 3 pods.
   4. Verifies the cassandra node joining status
 
The real goal here was to provide a baseline where the cassandra nodes have joined together.


### 4.2 Deployment-02 - Introducing a LoadBalancer
This deployment modifies the deployment manifests of Deployment-01 in the following ways:
   1. Changes the cassandra service to a type LoadBalancer
   2. Introduces the headless service for cassandra node joining
   3. Updates the statefulset Cassandra Seeds env for the headless service

The purpose of this is to provide an external interface for the simple java client to access
the cassandra cluster.

The deployment script ***deploy.sh*** within the scripts folder performs the following:
   1. Deploys a fresh minikube with minikube addons (dashboard, metallb);
   2. Configures metallb ip range
   3. Creates the cassandra namespace
   4. Deploys the service and the the statefulset with 3 pods.
   5. Verifies the cassandra node joining status
   6. Allows running of the simple java test program (eclipse, maven) 'learn.CassandraProto.java' 
      found in the proto-cass directory within this project.


### 4.3 Deployment-03 - Introducing Istio Ambient Mode with Kubernetes Gateway API
This deployment adds an external facing Kubernetes Gateway API gateway and TCPRoute for the
Cassandra nodes. This functionality is provided via Istio Ambient Mode with the Gateway
API CRDs. The changes to the deployment manifests from Deployment-02 are as follows:
   1. New kubernetes manifest gateway.yaml which contains a Gateway and TCPRoute.
   2. Removes type: LoadBalancer from the cassandra service

The purpose is to provide an unencrypted gateway route to the cassandra nodes.

The deployment script ***deploy.sh*** within the scripts folder performs the following:
   1. Deploys a fresh minikube with minikube addons (dashboard, metallb);
   2. Configures metallb ip range
   3. Deploys the Kubernetes Gateway API standard and experimental CRDs
   4. Deploys istio in ambient mode with Gateway API Crds
   5. Creates the cassandra namespace
   6. Deploys the service and the the statefulset with 3 pods.
   7. Verifies the cassandra node joining status
   8. Deploys the Gateway and TCPRoute
   9. Verifies the status of the Gateway deployment
   10. Allows running of the simple java test program (eclipse, maven) 'learn.CassandraProto.java' 
      found in the proto-cass directory within this project.


### 4.4 Deployment-04 - Introducing Cert-Manager for Gateway TLS terminated encryption
This deployment modifies the external connectivity to require TLS encryption from the java
client. The TLS encryption is terminated within the Cassandra namespace at the Gateway,
but intra Pod communication within the namespace uses mTLS provided by the Istio Ambient
mode. The changes to the kubernetes manifests from Development-03 are as follows:
   1. Adds a cert-manager root-tls-cert-issuer.yaml (Self signed root)
   2. Adds a cert-manager tls-cert-issuer.yaml with an Issuer and CA Certificate.
   3. Changes the service names to cql-svc and headless-svc
   4. Modifies statefulset Cassandra Seeds env for the 'headless-svc' change.
   5. Adds a Certificate (cassandra-credential) to the gateway.yaml
   6. Modifies the cassandra-gateway to support TLS with termination using the 
      cassandra-credential.
   7. Changes the listener port to 9041 within the gateway. The TCPRoute forwards traffic
      to 9042 of the cql-svc.

The purpose of this deployment is to provide TLS encryption from an external Java client
into the Cassandra namespace.

The deployment script ***deploy.sh*** within the scripts folder performs the following:
   1. Deploys a fresh minikube with minikube addons (dashboard, metallb);
   2. Configures metallb ip range
   3. Deploys the Kubernetes Gateway API standard and experimental CRDs
   4. Deploys istio in ambient mode with Gateway API Crds
   5. Deploys cert-manager gateway CRDs
   6. Deploys cert-manager with Gateway API support
   7. Creates the cassandra namespace
   8. Deploys the cert-manager root-tls-cert-issuer
   9. Deploys the cert-manager tls-cert-issuer
   10. Deploys the service and the the statefulset with 3 pods.
   11. Verifies the cassandra node joining status
   12. Deploys the Gateway, TCPRoute and Credential certificate
   13. Verifies the status of the Gateway deployment
   14. Labels the cassandra namespace to istio ambient mode which starts mTLS between Pods.
   15. Obtains the cassandra-credential ca.crt and copies it to the java client project resource directory.
   16. Allows running of the simple java test program (eclipse, maven) 'learn.CassandraTLS.java' 
      found in the proto-cass directory within this project.

## 5 Things to Remember
1. Cassandra seed node designations within the statefulset env are as follows:
   <Pod-name>.<headless-service-name>.<namespace>.svc.cluster.local:<Intra-Port>
   cassandra-0.headless-svc.cassandra.svc.cluster.local:7000
2. Each of the Deployment Scenarios has at least 1 Directory variable which you will
   need to update within the deploy.sh
   
