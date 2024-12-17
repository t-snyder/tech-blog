---
layout: readme
title: 02 - Learning Prototype with Ingress-Nginx, Cert-Manager and Hashicorp Vault.
permalink: /readme/
pinned: false
excerpt: Instructions for deploying basic ingress-ngingx ingress with both http and https - passthru only; Cert-Manager and Hashicorp Vault CA.
---
Github Project: [https://github.com/t-snyder/vault_cert-manager_ingress](https://github.com/t-snyder/vault_cert-manager_ingress)

## Purpose
The purpose of the prototype project is to demonstrate the configuration and use of ingress-nginx
ingress, along with managing certificates for TLS with Cert-Manager and Vault CA within the minikube environment.
The tests include http and https terminated at the ingress controller. Cert-manager is
used to generate and manage the life-cycle of self-signed certificates for TLS which are signed by Vault CA.

## Projects Included
The projects include the following tls end-points: 
   1. papaya - A simple pekko-http tls server with tls termination on the ingress.

## Project Components
This series of kubernetes Ingress and Gateway API learning prototypes were developed and tested 
using the following. If you are using a different OS such as windows or possibly a different flavor 
of Linux you may have to modify some of the scripts accordingly.

| Core Infrastructure | Version         |
| --------------- | --------------- |
| Minikube        | 1.34.0          |
| Kubernetes      | 1.31.0          |
| Docker          | 27.2.0          |
| OpenSSL         | 3.4.0           |

## Computer Configuration:

| Name            | Description                             |
| --------------- | --------------------------------------- |
| Ubuntu          | 20.04.6 LTS                             |
| Processor       | Intel® Core™ i7-7700K CPU @ 4.20GHz × 8 |
| Memory          | 64 GB                                   |

## Deploying the Core Infrastructure Dependencies
Instructions for deploying the Core Infrastructure Dependencies listed above are NOT included within this set
of Prototypes as there are numerous targeted deployment instructions for each better suited for your
particular OS.

## Dependencies Deployed within the Prototype Scripts

| Deployed Name | Version         |
| Cert-manager  | 1.15.3          |
| Ingress-nginx | 1.11.2          |
| Kubernetes Gateway API | 1.1.0  |
| Hashicorp Vault | 1.17.3        |
| Apache Pekko-http | 1.1.0         |

## Deployment Files
The prototype deployment has been separated into various shell script files based upon the core functions being deployed.

### Step-1-startMinikube.sh
Deploy a clean minikube and addons - dashboard and ingress.

### Step-2-deployVaultTLS.sh
In order to deploy Hashicorp Vault to kubernetes (minikube) for use with TLS transport there are prerequisite
keys, certificates and secrets which must be created and deployed. For a better understanding of this
process please read the Hashicorp Vault documentation for installing Vault to minikube with TLS enabled. The 
steps detailed within this script follow this documentation. The final step of this script is to 
install Vault via the official helm chart.

Hashicorp Vault Documentation
  1. https://developer.hashicorp.com/vault/tutorials/kubernetes/kubernetes-minikube-tls

### Step-3-deployVaultSetup.sh
Now that Vault has been deployed to Kubernetes, we need to perform basic configuration. Vault has been
deployed to 3 pods. These pods need to be initialized with the appropriate Shamir key shares and thresholds,
and then joined together via raft, and finally unsealed with the shamir keys generated at the start of
this script.

After performing these configuration steps we generate at vault login token for the cluster and login to the 
running vault system. Next the scripts perform several test functions to ensure that the Vault deployment has
been successful.

### Step-4-configVaultCA.sh

