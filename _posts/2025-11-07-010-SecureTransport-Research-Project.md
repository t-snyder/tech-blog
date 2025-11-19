---
layout: single
title: "SecureTransport Research Project - Parts 1 - 6"
date: 2025-11-08
categories: [Security, Cryptography, Kubernetes]
tags: [post-quantum, nats, mtls, multi-cluster]
excerpt: "A comprehensive research prototype exploring automated certificate rotation, post-quantum cryptography, and zero-trust messaging in distributed systems."
---

A research prototype messaging system exploring practical solutions to operational challenges in modern cryptographic infrastructure including evolution to post-quantum cryptography and automated short life rotation for certificates - both Intermediate and Leaf with zero service downtime.

## Series Overview

This multi-part series covers:

{% assign sorted_posts = site.posts | where: "series", "SecureTransport Research Prototype" | sort: "series_part" %}

{% for post in sorted_posts %}
### [Part {{ post.series_part }}: {{ post.title | remove: "Secure Transport Research Project - " | remove: "Part " | remove: post.series_part | remove: " - " }}]({{ post.url }})
{{ post.excerpt }}
{% endfor %}
