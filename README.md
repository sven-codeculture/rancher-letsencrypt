![Rancher 1.6 + Let's Encrypt = Awesome Sauce](https://raw.githubusercontent.com/vostronet/rancher-letsencrypt/master/hero.png)

# Let's Encrypt Certificate Manager for Rancher 1.6

[![Docker Pulls](https://img.shields.io/docker/pulls/vostronet/rancher-letsencrypt.svg?maxAge=8600)][hub]
[![License](https://img.shields.io/github/license/vostronet/rancher-letsencrypt.svg?maxAge=8600)]()

[hub]: https://hub.docker.com/r/vostro/rancher-letsencrypt/

A [Rancher](http://rancher.com/rancher/) service that obtains free SSL/TLS certificates from the [Let's Encrypt CA](https://letsencrypt.org/), adds them to Rancher's certificate store and manages renewal and propagation of updated certificates to load balancers.

#### Requirements
* Rancher Server >= v1.6.0 < 2.x


### How to use

Docker Image: vostro/rancher-letsencrypt

Configure via Enviroment Variables

- API_VERSION = (Production,Sandbox)
- CERT_NAME = nameofcertgenerated
- DNS_RESOLVERS = 8.8.8.8:53,8.8.4.4:53
- DOMAINS = www.google.com,www.cloudflare.com
- EMAIL = user@service.com
- EULA = Yes
- PROVIDER = 
    Aurora
    Azure
    CloudFlare
    DigitalOcean
    DNSimple
    Dyn
    Gandi
    NS1
    Ovh
    Route53
    Vultr
    StackPath
- PUBLIC_KEY_TYPE: RSA-2048
- RENEWAL_PERIOD_DAYS: '20'
- RENEWAL_TIME: '12'
- RUN_ONCE: 'false'


refer to https://go-acme.github.io/lego/dns/ for the appropriate env variables for your selected provider


### Storing certificate in shared storage volume

By default the created SSL certificate is stored in Rancher's certificate store for usage in Rancher load balancers.

You can specify a volume name to store account data, certificate and private key in a (host scoped) named Docker volume.
To share the certificates with other services you may specify a persistent storage driver (e.g. rancher-nfs).

See the README in the Rancher catalog for more information.

#### Configuration reference

You can either set environment variables or use Rancher Secrets for provider configuration.

https://go-acme.github.io/lego/dns/
