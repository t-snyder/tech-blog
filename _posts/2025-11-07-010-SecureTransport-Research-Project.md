---
layout: single
title: "SecureTransport Research Project - Parts 1 - 6"
date: 2025-11-08
categories: [Security, Cryptography, Kubernetes]
tags: [post-quantum, nats, mtls, multi-cluster]
excerpt: "A comprehensive research prototype exploring automated certificate rotation, post-quantum cryptography, and zero-trust messaging in distributed systems."
---

A research prototype messaging system exploring practical solutions to operational challenges in modern cryptographic infrastructure including evolution to post-quantum cryptography and automated short life rotation for certificates - both Intermediate and Leaf with zero service downtime.

- **Note** The initial draft of each of these blogs were generated using Claude Sonnet 4.5 within Copilot given a requested outline. It had access to all of the project code and scripts. This draft was then manually editted and specific sections were requested to be revised based upon manual review.

## Series Overview

This multi-part series covers:

{% assign sorted_posts = site.posts | where: "series", "SecureTransport Research Prototype" | sort: "series_part" %}

{% for post in sorted_posts %}
### [Part {{ post.series_part }}: {{ post.title | remove: "Secure Transport Research Project - " | remove: "Part " | remove: post.series_part | remove: " - " }}]({{ post.url | relative_url }})

{{ post.excerpt }}
{% endfor %}
