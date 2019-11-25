package letsencrypt

import (
	"fmt"
	// "os"

	legoChallenge "github.com/go-acme/lego/v3/challenge"

	"github.com/go-acme/lego/v3/providers/dns/auroradns"
	"github.com/go-acme/lego/v3/providers/dns/azure"
	"github.com/go-acme/lego/v3/providers/dns/cloudflare"
	"github.com/go-acme/lego/v3/providers/dns/digitalocean"
	"github.com/go-acme/lego/v3/providers/dns/dnsimple"
	"github.com/go-acme/lego/v3/providers/dns/dyn"
	"github.com/go-acme/lego/v3/providers/dns/gandi"
	"github.com/go-acme/lego/v3/providers/dns/ns1"
	"github.com/go-acme/lego/v3/providers/dns/ovh"
	"github.com/go-acme/lego/v3/providers/dns/route53"
	"github.com/go-acme/lego/v3/providers/dns/stackpath"
	"github.com/go-acme/lego/v3/providers/dns/vultr"
)

// ProviderOpts is used to configure the DNS provider
// used by the Let's Encrypt client for domain validation
type ProviderOpts struct {
	Provider Provider

	// // Aurora credentials
	// AuroraUserId   string
	// AuroraKey      string
	// AuroraEndpoint string

	// // AWS Route 53 credentials
	// AwsAccessKey string
	// AwsSecretKey string

	// // Azure credentials
	// AzureClientId       string
	// AzureClientSecret   string
	// AzureSubscriptionId string
	// AzureTenantId       string
	// AzureResourceGroup  string

	// // CloudFlare credentials
	// CloudflareEmail string
	// CloudflareKey   string

	// // DigitalOcean credentials
	// DoAccessToken string

	// // DNSimple credentials
	// DNSimpleEmail string
	// DNSimpleKey   string

	// // Dyn credentials
	// DynCustomerName string
	// DynUserName     string
	// DynPassword     string

	// // Gandi credentials
	// GandiApiKey string

	// // NS1 credentials
	// NS1ApiKey string

	// // OVH credentials
	// OvhApplicationKey    string
	// OvhApplicationSecret string
	// OvhConsumerKey       string

	// // Vultr credentials
	// VultrApiKey string
}

type Provider string

const (
	AURORA       = Provider("Aurora")
	AZURE        = Provider("Azure")
	CLOUDFLARE   = Provider("CloudFlare")
	DIGITALOCEAN = Provider("DigitalOcean")
	DNSIMPLE     = Provider("DNSimple")
	DYN          = Provider("Dyn")
	GANDI        = Provider("Gandi")
	NS1          = Provider("NS1")
	OVH          = Provider("Ovh")
	ROUTE53      = Provider("Route53")
	VULTR        = Provider("Vultr")
	// HTTP         = Provider("HTTP")
	STACKPATH = Provider("StackPath")
)

type ProviderFactory struct {
	factory   interface{}
	challenge legoChallenge.Type
}

var providerFactory = map[Provider]ProviderFactory{
	STACKPATH:    ProviderFactory{makeStackPathProvider, legoChallenge.DNS01},
	AURORA:       ProviderFactory{makeAuroraProvider, legoChallenge.DNS01},
	AZURE:        ProviderFactory{makeAzureProvider, legoChallenge.DNS01},
	CLOUDFLARE:   ProviderFactory{makeCloudflareProvider, legoChallenge.DNS01},
	DIGITALOCEAN: ProviderFactory{makeDigitalOceanProvider, legoChallenge.DNS01},
	DNSIMPLE:     ProviderFactory{makeDNSimpleProvider, legoChallenge.DNS01},
	DYN:          ProviderFactory{makeDynProvider, legoChallenge.DNS01},
	GANDI:        ProviderFactory{makeGandiProvider, legoChallenge.DNS01},
	NS1:          ProviderFactory{makeNS1Provider, legoChallenge.DNS01},
	OVH:          ProviderFactory{makeOvhProvider, legoChallenge.DNS01},
	ROUTE53:      ProviderFactory{makeRoute53Provider, legoChallenge.DNS01},
	VULTR:        ProviderFactory{makeVultrProvider, legoChallenge.DNS01},
	// HTTP:         ProviderFactory{makeHTTPProvider, lego.HTTP01},
}

func getProvider(opts ProviderOpts) (legoChallenge.Provider, legoChallenge.Type, error) {
	if f, ok := providerFactory[opts.Provider]; ok {
		provider, err := f.factory.(func(ProviderOpts) (legoChallenge.Provider, error))(opts)
		if err != nil {
			return nil, f.challenge, err
		}
		return provider, f.challenge, nil
	}
	irrelevant := legoChallenge.DNS01
	return nil, irrelevant, fmt.Errorf("Unsupported provider: %s", opts.Provider)
}

func makeStackPathProvider(opts ProviderOpts) (legoChallenge.Provider, error) {
	provider, err := stackpath.NewDNSProvider()
	if err != nil {
		return nil, err
	}
	return provider, nil
}

// returns a preconfigured Aurora legoChallenge.Provider
func makeAuroraProvider(opts ProviderOpts) (legoChallenge.Provider, error) {
	provider, err := auroradns.NewDNSProvider()
	if err != nil {
		return nil, err
	}

	return provider, nil
}

// returns a preconfigured CloudFlare legoChallenge.Provider
func makeCloudflareProvider(opts ProviderOpts) (legoChallenge.Provider, error) {
	provider, err := cloudflare.NewDNSProvider()
	if err != nil {
		return nil, err
	}
	return provider, nil
}

// returns a preconfigured DigitalOcean legoChallenge.Provider
func makeDigitalOceanProvider(opts ProviderOpts) (legoChallenge.Provider, error) {
	provider, err := digitalocean.NewDNSProvider()
	if err != nil {
		return nil, err
	}
	return provider, nil
}

// returns a preconfigured Route53 legoChallenge.Provider
func makeRoute53Provider(opts ProviderOpts) (legoChallenge.Provider, error) {
	provider, err := route53.NewDNSProvider()
	if err != nil {
		return nil, err
	}
	return provider, nil
}

// returns a preconfigured DNSimple legoChallenge.Provider
func makeDNSimpleProvider(opts ProviderOpts) (legoChallenge.Provider, error) {
	provider, err := dnsimple.NewDNSProvider()
	if err != nil {
		return nil, err
	}
	return provider, nil
}

// returns a preconfigured Dyn legoChallenge.Provider
func makeDynProvider(opts ProviderOpts) (legoChallenge.Provider, error) {
	provider, err := dyn.NewDNSProvider()
	if err != nil {
		return nil, err
	}
	return provider, nil
}

// returns a preconfigured Vultr legoChallenge.Provider
func makeVultrProvider(opts ProviderOpts) (legoChallenge.Provider, error) {
	provider, err := vultr.NewDNSProvider()
	if err != nil {
		return nil, err
	}
	return provider, nil
}

// returns a preconfigured Ovh legoChallenge.Provider
func makeOvhProvider(opts ProviderOpts) (legoChallenge.Provider, error) {
	provider, err := ovh.NewDNSProvider()
	if err != nil {
		return nil, err
	}
	return provider, nil
}

// returns a preconfigured Gandi legoChallenge.Provider
func makeGandiProvider(opts ProviderOpts) (legoChallenge.Provider, error) {
	provider, err := gandi.NewDNSProvider()
	if err != nil {
		return nil, err
	}
	return provider, nil
}

// // returns a preconfigured HTTP legoChallenge.Provider
// func makeHTTPProvider(opts ProviderOpts) (legoChallenge.Provider, error) {
// 	provider := lego.NewHTTPProviderServer("", "")
// 	return provider, nil
// }

// returns a preconfigured Azure legoChallenge.Provider
func makeAzureProvider(opts ProviderOpts) (legoChallenge.Provider, error) {

	provider, err := azure.NewDNSProvider()
	if err != nil {
		return nil, err
	}
	return provider, nil
}

// returns a preconfigured NS1 legoChallenge.Provider
func makeNS1Provider(opts ProviderOpts) (legoChallenge.Provider, error) {
	provider, err := ns1.NewDNSProvider()
	if err != nil {
		return nil, err
	}
	return provider, nil
}
