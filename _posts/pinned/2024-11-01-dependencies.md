---
layout: readme
excerpt: Please read. Environment used for developing and testing ingress and kubernetes gateway api prototypes
seo_title: Dependencies for Minikube based Ingress and Kubernetes Gateway API prototype series, including Istio, Vault, and Cert-Manager 
seo_description: A post listing the dependencies for a series of posts explaining the implementation of prototypes built upon minikube kubernetes using ingress-nginx, istio in ambient mode, kubernetes gateway API, hashicorp vault, and metallb.
pinned: true
---

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

## Dependencies Deployed within the Prototype Scripts ( As Required )

| Deployed Name | Version         |
| Cert-manager  | 1.15.3          |
| Ingress-nginx | 1.11.2          |
| Istio         | 1.23.2          |
| Kubernetes Gateway API | 1.1.0  |
| Hashicorp Vault | 1.17.3        |
| Metallb         | 0.9.6         |
| Apache Pekko-http | 1.1.0         |


## Deploying Prototypes
The various scripts provided for deploying each of the prototypes **are NOT automated
scripts**. The bash or sh script portions are designed to be copy/pasted ( generally on a per line/cmd basis )
into a linux terminal. There are several reasons for this:
  1. The purpose is learning. Explicitly following each step enhances the learning.
  2. In different places the scripts log into a running pod in order to perform certain activities.
  3. In certain prototypes, the Vault UI is used.
  
  
