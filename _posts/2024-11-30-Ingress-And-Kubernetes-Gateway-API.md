---
layout: single
title: "Ingress and Kubernetes Gateway API Learning Projects"
date: 2024-11-30
categories: [Kubernetes, DevOps, Networking]
tags: [ingress, gateway-api, istio, cert-manager, nginx, vault]
excerpt: "A comprehensive series exploring Kubernetes ingress controllers, Gateway API implementations, and advanced certificate management with Cert-Manager, Vault, and Istio Ambient Mode."
---

This series of prototypes demonstrates the evolution from traditional Kubernetes Ingress to the new Gateway API, exploring various implementations and certificate management strategies in Minikube environments.

## Series Overview

The projects progress from basic ingress configurations to advanced Gateway API implementations with production-grade certificate management.

{% assign sorted_posts = site.posts | where: "series", "Ingress and Kubernetes Gateway API" | sort: "series_part" %}

{% for post in sorted_posts %}
### [Part {{ post.series_part }}: {{ post.title }}]({{ post.url | relative_url }})

{{ post.excerpt }}

---
{% endfor %}

## Learning Path

1. **Start with Deploy-01** to understand basic ingress concepts
2. **Progress to Deploy-02** to learn certificate management with Vault
3. **Move to Deploy-03** to understand Gateway API fundamentals
4. **Explore Deploy-04** to compare different Gateway API implementations
5. **Complete with Deploy-05** for production-ready configurations
6. **Review Thoughts and Conclusions** for lessons learned

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
