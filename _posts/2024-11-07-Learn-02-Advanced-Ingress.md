---
layout: readme
title: 02 - Learn-02-Advanced-Ingress
pinned: false
excerpt: Project deploying ingress-ngingx ingress with both http and https-passthru only; Cert-Manager and Hashicorp Vault CA.
---
Github Project: [https://github.com/t-snyder/learn-02-advanced-ingress](https://github.com/t-snyder/learn-02-advanced-ingress)

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
| Hashicorp Vault | 1.17.3        |
| Apache Pekko-http | 1.1.0         |

## Deployment Files
The prototype deployment has been separated into various shell script files based upon the core functions being
deployed.<br> 
**Note -** *The commands within the shell files below are meant to be copy pasted (one or a few lines at a time) into a terminal,
and not run as an automated bash script.*

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
Hashicorp Vault has now been setup and configured with TLS transport. The next step is to setup Vault as a
Certificate Authority (CA) providing both a Root Certificate as well as an Intermediate Certificate for signing.
This will allow Cert-Manager to send Vault Certificate Signing Requests (CSR) and receive back the signed
certificate. Please note that these certificates will still be self signed Certificates for this prototype.

Hashicorp Vault documentation provides multiple methods for configuring and enabling the Vault CA. Within this
prototype I have used the Vault UI to generate the Root and Intermediate Certificates and associated Policies,
Roles and Issuers. The main reason is that I got it to work using the UI, and while trying to configure the CA
using the Vault CLI, I ended up with errors generating the final certificates. As I had a working solution I moved
on. 

Hashicorp Vault Documentation for Configuring Vault as a CA
  1. https://developer.hashicorp.com/vault/tutorials/pki/pki-engine
  
### Step-5-vaultIssuerSetup.sh
Now that the Vault Root and Intermediate PKI engines have been setup to allow the the intermediate CA
to sign certificates we need to configure Vault Issuers which Cert-Manager can automatically access for
CSR requests. What this means in scripting terms is we need to:
  1. Create and deploy a Vault policy to manage access rights.
  2. Enable Kubernetes Authentication within Vault.
  3. Create a Kubernetes Authentication Role and bind it to a service account.
  4. Create a Kubernetes secret for the Issuer service account.
  5. Create and apply the Cert-Manager Issuer which points to the Vault Issuer with appropriate Authentication.
  6. Define a test certificate.
  7. Create and review the signed test certificate.
 
 Various documentation:
   1. https://cert-manager.io/docs/configuration/vault/
   2. https://medium.com/nerd-for-tech/using-hashicorp-vault-as-a-certificate-issuer-in-cert-manager-9e19d7239d3d
 
 
### Step-6-PapayaSetup.sh
We have now completed the prepatory setup. In this stage we are going to deploy the Pekko-http echo server Papaya.
 
***Please note that the script assumes that the Papaya image has been already generated from the first prototype, so the
 steps are NOT replicated within this script.***
 
The scripts involves using the Vault Ui to generate a new Intermediate CA and associated Role. The scripting then
deploys the various Papaya artifacts - cert-manager issuer, kubernetes service account, pvc, and finally the Papaya app.
 
The script then provides a test of the deployment.
 
