---
layout: readme
title: 01 - Basic ingress-nginx http and https-with termination prototype.
permalink: /proto-001/
pinned: false
excerpt: Shell instructions for deploying basic ingress-ngingx ingress with both http and https termination. Uses ingress-nginx, cert-manager, peeko-http
---
Github Project: [https://github.com/t-snyder/learn-01-basic-ingress](https://github.com/t-snyder/learn-01-basic-ingress)

## Purpose
The purpose of the prototype project is to demonstrate the configuration and use of ingress-nginx, and then increasing 
complexity with Cert-Manager and Pekko-Http within the minikube environment. The tests include http and https terminated at the ingress controller. Cert-manager is
used to manage self-signed certificates for the TLS.

## Projects Included
The projects include the following sub-projects: 
   1. fruit-deploy - Deploys all components to a minikube environment. 
   2. passionfruit - Deploys a simple pekko-http server with an http ingress. 
   3. papaya       - A simple pekko-http tls server with tls termination on the ingress.

## Project Components
The main components of the prototype project are: 
   - kubernetes via minikube 
   - cert-manager for certificate generation 
   - ingress-nginx for controller reverse proxy and ingress configuration management. 
   - apache pekko-http as an http server

## Deployment Assumptions
The project deployment presumes the following:
   1. Clone fruit-deploy, passionfruit and papaya projects to the same directory.
   2. Running minikube environment - I have been using the following commands to start and restart minikube. 
         1. minikube delete 
         2. minikube start --cpus 4 --memory 12288 --vm-driver kvm2 --disk-size 100g --insecure-registry="192.168.39.0/24" 
         3. minikube addons enable dashboard 
         4. minikube addons enable ingress
   3. Linux machine. I use Ubuntu 20.04 There are several utility commands within deployKube.sh which are linux specific. These can easily be modified or removed for your operating system environment.

## Runtime Instructions:
  1. Open the fruit-deploy/scripts/deployKube.sh file within a text editor. 
  2. Open a terminal to process the commands. 
  3. Modify the $PROTODIR env variable in the terminal to point to your source directory.
  4. Run the commands within the fruit-deploy/scripts/deployKube.sh separately.
     **Note -**<br> 
      *The commands within the deployKube.sh are meant to be copy pasted into a terminal and not run as a bash script.*

## Testing
At the end of the deployKube.sh file there is a section for curl commands to invoke various deployed capabilities. A brief summary of the capabilites are:
  1. Both apple and banana support a path based http ingress to an echo server, as well as a host based ingress for invoking the echo server. The configurations for these can be found in 
     - Configuration - kube/apple-path.yaml Deployment Test - curl -kL http://$ipAddr/apple 
     - Configuration - kube/apple-host.yaml Deployment Test - curl -kL http://apple.foo.com/apple 
     - Configuration - kube/banana-path.yaml Deployment Test - curl -kL http://$ipAddr/banana 
     - Configuration - kube/banana-host.yaml Deployment Test - curl -kL http://banana.foo.com/banana
  2. mango supports an https request with tls passthrough to the echo server and cert-manager certificate generation. 
     - Configuration - kube/mango.yaml; tls - mango-tls-cert-issuer.yaml 
     - Deployment Test - curl -kL https://mango.foo.com/mango
  3. passion supports an http request to a simple pekko-http server 
     - Configuration - passionfruit.yaml 
     - Deployment Test - curl -kL http://passion.foo.com/passion
  4. papaya supports an https request to a simple pekko-http server with tls termination at the ingress, as well as cert-manager certificate generation.
     - Configuration - papaya.yaml;
     - secret - papaya-auth.yaml;
     - pvc - papaya-pvc.yaml;
     - tls - papaya-tls-cert-issuer.yaml
     - Deployment Test - curl -kL https://papaya.foo.com/papaya
