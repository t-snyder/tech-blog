---
layout: readme
title: 05 - Learn-05-Advanced-Gateway-API
permalink: /learn-05/
pinned: false
excerpt: Deploys a functional prototype using Kubernetes Gateway API supporting TLS Termination and Passthru 
ingress functionality. Built using Istio (Ambient Mode), Cert-Manager and Hashicorp Vault for
certificate lifecycle management and signing TLS certificates within a Minikube environment.
---
Github Project: [https://github.com/t-snyder/learn-05-advanced-gateway-api](https://github.com/t-snyder/learn-05-advanced-gateway-api)

# Learn-05-Advanced-Gateway-API

## Project Purpose
Deploys a functional prototype using Kubernetes Gateway API supporting TLS Termination and Passthru 
ingress functionality. Built using Istio (Ambient Mode), Cert-Manager and Hashicorp Vault for
certificate lifecycle management and signing TLS certificates within a Minikube environment.

## Project Dependencies
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
| ------------- | --------------- |
| Cert-manager  | 1.15.3          |
| Ingress-nginx | 1.11.2          |
| Istio         | 1.23.2          |
| Kubernetes Gateway API | 1.1.0  |
| Hashicorp Vault | 1.17.3        |
| Metallb         | 0.9.6         |

## Dependency Documentation Referenced
  1. Cert-Manager / Vault Issuer - https://cert-manager.io/docs/configuration/vault/
  2. Cert-Manager / Vault - https://developer.hashicorp.com/vault/tutorials/archive/kubernetes-cert-manager
  3. Cert-Manager Kubenetes Service Account - https://github.com/cert-manager/cert-manager/pull/5502 - new serviceaccountref
  4. Vault Minikube TLS - https://developer.hashicorp.com/vault/tutorials/kubernetes/kubernetes-minikube-tls
  5. Configure Vault as a CA - https://developer.hashicorp.com/vault/tutorials/pki/pki-engine
  
   
## Prototype Script Functionality
**Note :**<br>
*The commands within the shell files below are meant to be copy pasted (one or a few lines at a time) into a terminal, and not run as an automated bash script.*


### Step 01-Deploy Minikube, metallb, Gateway API CRDs, Istio, Cert-Manager
This script deploys the following:
  1. Deletes and Installs Fresh Minikube install.
  2. Installs and configures Metallb load balancer.
  3. Installs Kubernetes Gateway API CRDs, both standard and experimental
  4. Installs Istio in Ambient Mode with Experimental Gateway CRDs turned on.
  5. Creates cert-manager namespace
  6. Intalls Cert-Manager CRDs
  7. Installs Cert-Manager with Experimental Gateway CRD support.


### Step 02-Configure Vault TLS, Intall Vault
In order to deploy Hashicorp Vault to kubernetes (minikube) for use with TLS transport there are prerequisite
keys, certificates and secrets which must be created and deployed. For a better understanding of this
process please read the Hashicorp Vault documentation (above) for installing Vault to minikube with TLS enabled. The 
steps detailed within this script follow this documentation. The final step of this script is to 
install Vault via the official helm chart.

The steps performed within the script to accomplish this are:
  1. Generate OpenSSL keys and certificates for vault.
  2. Create a CSR (certificate signing request)
  3. Have Kubernetes CA sign the CSR and approve the certificate
  4. Create the vault namespace
  5. Use the keys and certificates to create a kubernetes secret for Vault.
  6. Install Hashicorp Vault

  
### Step 03-Initialize Vault Setup (Join, Unseal)
Now that Vault has been deployed to Kubernetes (Minikube), we need to perform basic configuration. Vault has been
deployed to 3 pods. These pods need to be initialized with the appropriate Shamir key shares and thresholds,
and then joined together via raft, and finally unsealed with the shamir keys generated at the start of
this script.

After performing these configuration steps we generate at vault login token for the cluster and login to the 
running vault system. Next the scripts perform several test functions to ensure that the Vault deployment has
been successful.

The steps within the script are as follows:
  1. Generate the shamir key with the appropriate keyshare and key threshhold - (1 and 1)
  2. Obtain the resulting unseal key
  3. Unseal Vault-0 pod
  4. Join Vaults pods 1 and 2 to Vault-0 pod
  5. Unseal Vault pods 1 and 2
  6. Obtain the Vault root cluster token
  7. Login to the Vault pod 0
  8. Validate and Test the Vault setup

  
### Step 04-Configure Vault CA
Hashicorp Vault has now been setup and configured with TLS transport. The next step is to setup Vault as a
Certificate Authority (CA) providing both a Root Certificate as well as an Intermediate Certificate for signing.
This will allow Cert-Manager to send Vault Certificate Signing Requests (CSR) and receive back the approved signed
certificate. Please note that these certificates will still be self signed Certificates for this prototype.

Hashicorp Vault documentation provides multiple methods for configuring and enabling the Vault CA. Within this
prototype I have used the Vault UI to generate the Root and Intermediate Certificates and associated Policies,
Roles and Issuers. The main reason is that I got it to work using the UI, and while trying to configure the CA
using the Vault CLI, I ended up with errors generating the final certificates. As I had a working solution I moved
on. See setting up Vault as a CA in the documentation section above.

The steps within the script are as follows:
  1. Create a Vault Admin policy for access rights.
  2. Generate an Admin Token to be used for UI login
  3. Login to the Vault UI
  4. Create and configure a PKI engine for the root CA.
  5. Create a role for the root CA.
  6. Create a new PKI engine for the Intermediate CA.
  7. Generate and intermediate CSR for the Intermediate CA.
  8. Have the Root CA sign the Intermediate CSR
  9. Import the signed Certificate to the Intermediate CA
  10. Create an Intermediate CA Role
  11. Test by generating a new certificate from the Intermediate CA
 
  
### Step 05-Configure Vault Kubernetes Auth
Now that the Vault Root and Intermediate PKI engines have been setup to allow the the intermediate CA
to sign certificates we need to configure Vault Kubernetes auth so that Cert-Manager can automatically
access Vault Issuers for CSR requests. What this means in scripting terms is we need to:
  1. Enable Kubernetes Authentication within Vault.
  2. Create a Kubernetes Authentication Role and bind it to a service account.


### Step 06-Configure SvcAcctRef Vault Auth
Now we need to configure Vault Issuers so that Cert-Manager can automatically access Vault for
CSR requests. What this means in scripting terms is we need to:
  1. Create a Vault Issuer Role.
  2. Create a Vault Policy to allow signing for CSRs.
  3. Configure the Vault Issuer Role.
  4. Create the Service Account, Role, Role binding Vault-Issuer cert-manager component.
  5. Create and apply the Cert-Manager Issuer which points to the Vault Issuer with appropriate Authentication.
  6. Define a test certificate.
  7. Create and review the signed test certificate. 
  

### Step 07-Configure Mango with TLS Termination
The Mango App is an Http Echo Server which upon a successful request returns "Juicy Mango".
The purpose of including this within this prototype is to show support for multiple Gateways
each within a separate namespace using differing Route configurations. As this configuration
supports TLS termination at the Gateway with mutual TLS from the Gateway to the service
endpoint the configuration uses an HTTPRoute.

The steps performed within this script are as follows:
  1. Create a namespace for the mango deployment
  2. Create and configure a Vault Issuer and role for mango certificates
  3. Create a vault authorization policy and role for the mango issuer
  4. Deploy cert-manager Service Account, Role and Rolebindings for the issuer
  5. Deploy a cert-manager issuer configured to the vault mango-issuer
  6. Deploy a cert-manager certificate for mango tls using vault mango issuer
  7. Deploy mango gateway and app
  8. Obtain mango host, ports, and tls credentials
  9. Test access via curl with tls terminated at the gateway and mtls within cluster.


### Step 08-Configure Nginx with TLS Passthru
The Nginx Server deployments deploys a standard Nginx Web Server to an Nginx namespace.
Within this namespace is also deployed a dedicated Gateway for the nginx deployment. The
Gateway configuration for the service endpoints use a TLSRoute which supports TLS
Passthrough. The successful setup and test verify that multiple Gateways in differing 
namespaces supporting differing Route types are supported within the Istio Gateway
controller.

The steps performed within this script are as follows:
  1. Create a namespace for the nginx deployment
  2. Create and configure a Vault Issuer and role for nginx certificate signing
  3. Create a vault authorization policy and role for the nginx issuer
  4. Deploy cert-manager Service Account, Role and Rolebindings for the issuer
  5. Deploy a cert-manager issuer configured to the vault nginx-issuer
  6. Deploy a cert-manager certificate for nginx tls using vault nginx issuer
  7. Deploy nginx gateway and app
  8. Obtain nginx host, ports, and tls credentials
  9. Test access via curl with tls passthru via the gateway to the nginx app listener.

