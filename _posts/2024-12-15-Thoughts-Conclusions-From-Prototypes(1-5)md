---
layout: readme
title: Thoughts - Conclusions from Learning Prototypes 1-5
excerpt: Conclusions reached from implementing Ingress and Gateway API prototypes with Cert-Manager, Vault and Istio (Ambient Mode)
pinned: false
---

## Prototypes Explanation

The Learning prototypes provided within this blog (1-5) provide various deployment scenarios
of Kubernetes Ingress and Kubernetes Gateway API. In addition the prototypes are extended to 
integrate with Cert-Manager to manage the TLS certificate lifecycle, and Hashicorp Vault for 
certificate signing. 

For the individual prototype functionality please review the associated Blog post and deployment scripts.

## Conclusions Reached
Based upon the deployment scenarios tested, the clear winner and going forward strategy for 
me is the Kubernetes Gateway API using Istio Ambient Gateway Controller and associated CRDs.
The major reasons for this recommendation is:
  1. Istio Gateway provides the ability to configure multiple Gateway objects in differing namespaces which support differing types of Routes.
  2. Ingress-nginx in supporting TLS Passthru requires Passthru for all the cluster.
  3. Nginx Gateway Fabric only allows a single Gateway object per kubernetes cluster. As such it is less interesting to me.
  4. Istio Gateway integrates well with Cert-Manager.


  
