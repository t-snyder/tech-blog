---
layout: single
title: "SecureTransport Research Project - Parts 1 - 6"
date: 2025-11-08
categories: [Security, Cryptography, Kubernetes]
tags: [post-quantum, nats, mtls, multi-cluster]
excerpt: "A comprehensive research prototype exploring automated certificate rotation, post-quantum cryptography, and zero-trust messaging in distributed systems."
---

A research prototype messaging system exploring practical solutions to operational challenges in modern cryptographic infrastructure including evolution to post-quantum 
cryptography and automated short life rotation for certificates - both Intermediate and Leaf with zero service downtime.

## Series Overview

This multi-part series covers:

{% assign sorted_posts = site.posts | where: "series", "SecureTransport Research Prototype" | sort: "series_part" %}

{% for post in sorted_posts %}
### [Part {{ post.series_part }}: {{ post.title | remove: "Secure Transport Research Project - " | remove: "Part " | remove: post.series_part | remove: " - " }}]({{ post.url }})
{{ post.excerpt }}
{% endfor %}

## Quick Links

- [Part 1 - Overview]({% post_url 2025-11-08-010-SecureTransport-Overview-Part-1 %})
- [Part 2 - Installation]({% post_url 2025-11-09-010-SecureTransport-Installation %})
- [Part 3 - Service Authorization]({% post_url 2025-11-10-010-SecureTransport-ServiceAuthorization %})
- [Part 4 - Automated Certificate Rotation]({% post_url 2025-11-12-010-SecureTransport-AutomatedCertificateRotation %})
- [Part 5 - OpenBao Integration]({% post_url 2025-11-13-010-SecureTransport-OpenBaoIntegration %})
- [Part 6 - SignedMessage Protocol]({% post_url 2025-11-14-010-SecureTransport-SignedMessage %})
