---
layout: single
title: "Server Deployment Learning Projects"
date: 2025-03-25
categories: [Kubernetes, Databases, Security]
tags: [cassandra, pulsar, etcd, encryption, minikube]
excerpt: "A collection of deployment prototypes exploring various server technologies including Apache Cassandra, Apache Pulsar, and Kubernetes etcd encryption in Minikube environments."
---

This series focuses on deploying and configuring various server technologies within Kubernetes/Minikube environments, with emphasis on security, connectivity, and operational best practices.

## Series Overview

{% assign sorted_posts = site.posts | where: "series", "Server Deployments" | sort: "series_part" %}

{% for post in sorted_posts %}
### [Part {{ post.series_part }}: {{ post.title }}]({{ post.url | relative_url }})

{{ post.excerpt }}

---
{% endfor %}

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
