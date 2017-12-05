package main

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/janeczku/rancher-letsencrypt/letsencrypt"
	"github.com/janeczku/rancher-letsencrypt/rancher"
)

const (
	CERT_DESCRIPTION    = "Created by Let's Encrypt Certificate Manager"
	ISSUER_PRODUCTION   = "Let's Encrypt"
	ISSUER_STAGING      = "fake CA"
	RENEWAL_PERIOD_DAYS = 20
)

type Certificate struct {
	TLD               string
	CommonName        string
	AltNames          []string
	KeyType           string

	ExpiryDate        time.Time

	RancherCertId string
	Acme    *letsencrypt.Client
}

type Context struct {
	Rancher *rancher.Client

	AdminEmail   string
	ServiceLabel string
	Certificates []Certificate
	LeApiVersion letsencrypt.ApiVersion
	RenewalDayTime    int
	RenewalPeriodDays int

	Debug    bool
	TestMode bool
	RunOnce  bool
}

// InitContext initializes the application context from environmental variables
func (c *Context) InitContext() {
	var err error
	c.Debug = debug
	c.TestMode = testMode
	c.ServiceLabel = getEnvOption("SERVICE_LABEL", true)
	c.AdminEmail = getEnvOption("EMAIL", true)
	cattleUrl := getEnvOption("CATTLE_URL", true)
	cattleApiKey := getEnvOption("CATTLE_ACCESS_KEY", true)
	cattleSecretKey := getEnvOption("CATTLE_SECRET_KEY", true)
	eulaParam := getEnvOption("EULA", false)
	apiVerParam := getEnvOption("API_VERSION", true)
	c.LeApiVersion = letsencrypt.ApiVersion(apiVerParam)

	dayTimeParam := getEnvOption("RENEWAL_TIME", true)
	// providerParam := getEnvOption("PROVIDER", false) //true
	resolversParam := getEnvOption("DNS_RESOLVERS", false)
	renewalDays := getEnvOption("RENEWAL_PERIOD_DAYS", false)
	runOnce := getEnvOption("RUN_ONCE", false)

	if b, err := strconv.ParseBool(runOnce); err == nil {
		c.RunOnce = b
	} else {
		c.RunOnce = false
	}

	if i, err := strconv.Atoi(renewalDays); err == nil {
		c.RenewalPeriodDays = i
	} else {
		c.RenewalPeriodDays = RENEWAL_PERIOD_DAYS
	}

	if eulaParam != "Yes" {
		logrus.Fatalf("Terms of service were not accepted")
	}

	dnsResolvers := []string{}
	if len(resolversParam) > 0 {
		for _, resolver := range listToSlice(resolversParam) {
			if !strings.Contains(resolver, ":") {
				resolver += ":53"
			}
			dnsResolvers = append(dnsResolvers, resolver)
		}
	}

	c.RenewalDayTime, err = strconv.Atoi(dayTimeParam)
	if err != nil || c.RenewalDayTime < 0 || c.RenewalDayTime > 23 {
		logrus.Fatalf("Invalid value for RENEWAL_TIME: %s", dayTimeParam)
	}


	c.Rancher, err = rancher.NewClient(cattleUrl, cattleApiKey, cattleSecretKey)
	if err != nil {
		logrus.Info("FATAL")
		logrus.Fatalf("Could not connect to Rancher API: %v", err)
	}

	// Enable debug mode
	if c.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}
}

func (c *Context) GetLetsEncryptClient(emailParam string, keyType string, apiVersion letsencrypt.ApiVersion, providerParam string) *letsencrypt.Client {
	var err error
	providerOpts := letsencrypt.ProviderOpts{
		Provider:             letsencrypt.Provider(providerParam),
		AzureClientId:        getEnvOption("AZURE_CLIENT_ID", false),
		AzureClientSecret:    getEnvOption("AZURE_CLIENT_SECRET", false),
		AzureSubscriptionId:  getEnvOption("AZURE_SUBSCRIPTION_ID", false),
		AzureTenantId:        getEnvOption("AZURE_TENANT_ID", false),
		AzureResourceGroup:   getEnvOption("AZURE_RESOURCE_GROUP", false),
		AuroraUserId:         getEnvOption("AURORA_USER_ID", false),
		AuroraKey:            getEnvOption("AURORA_KEY", false),
		AuroraEndpoint:       getEnvOption("AURORA_ENDPOINT", false),
		CloudflareEmail:      getEnvOption("CLOUDFLARE_EMAIL", false),
		CloudflareKey:        getEnvOption("CLOUDFLARE_KEY", false),
		DoAccessToken:        getEnvOption("DO_ACCESS_TOKEN", false),
		AwsAccessKey:         getEnvOption("AWS_ACCESS_KEY", false),
		AwsSecretKey:         getEnvOption("AWS_SECRET_KEY", false),
		DNSimpleEmail:        getEnvOption("DNSIMPLE_EMAIL", false),
		DNSimpleKey:          getEnvOption("DNSIMPLE_KEY", false),
		DynCustomerName:      getEnvOption("DYN_CUSTOMER_NAME", false),
		DynUserName:          getEnvOption("DYN_USER_NAME", false),
		DynPassword:          getEnvOption("DYN_PASSWORD", false),
		VultrApiKey:          getEnvOption("VULTR_API_KEY", false),
		OvhApplicationKey:    getEnvOption("OVH_APPLICATION_KEY", false),
		OvhApplicationSecret: getEnvOption("OVH_APPLICATION_SECRET", false),
		OvhConsumerKey:       getEnvOption("OVH_CONSUMER_KEY", false),
		GandiApiKey:          getEnvOption("GANDI_API_KEY", false),
		NS1ApiKey:            getEnvOption("NS1_API_KEY", false),
	}

	acme, err := letsencrypt.NewClient(emailParam, letsencrypt.KeyType(keyType), apiVersion, []string{}, providerOpts)
	if err != nil {
		logrus.Fatalf("LetsEncrypt client: %v", err)
	}

	logrus.Infof("Using Let's Encrypt %s API", apiVersion)
	acme.EnableLogs()
	return acme
}

func (c *Context) BuildCertificatesFromServiceLabel(service string) []Certificate {
	var storedLocally, storedInRancher bool
	certsFound := c.parseServiceLabel(service)
	for i, baseCert := range certsFound {
		logrus.Infof("%v", baseCert)
		acmeClient := c.GetLetsEncryptClient(c.AdminEmail, baseCert.KeyType, c.LeApiVersion, "HTTP")
		ok, acmeCert := acmeClient.GetStoredCertificate(baseCert.CommonName, baseCert.AltNames)
		if ok {
			storedLocally = true
			certsFound[i].ExpiryDate = acmeCert.ExpiryDate
			logrus.Infof("Found locally stored certificate '%s'", baseCert.CommonName)
		}

		rancherCert, err := c.Rancher.FindCertByName(baseCert.CommonName)
		if err != nil {
			logrus.Fatalf("Could not lookup certificate in Rancher API: %v", err)
		}

		if rancherCert != nil {
			storedInRancher = true
			certsFound[i].RancherCertId = rancherCert.Id
			logrus.Infof("Found existing certificate '%s' in Rancher", baseCert.CommonName)
		}

		if storedLocally && storedInRancher {
			if rancherCert.SerialNumber != acmeCert.SerialNumber {
				logrus.Infof("Serial number mismatch between Rancher and local certificate '%s'", baseCert.CommonName)
				c.updateRancherCert(baseCert.CommonName, rancherCert.Id, acmeCert.PrivateKey, acmeCert.Certificate)
			}
		} else if storedLocally && !storedInRancher {
			logrus.Debugf("Adding certificate '%s' to Rancher", baseCert.CommonName)
			certsFound[i].RancherCertId = c.addRancherCert(baseCert.CommonName, acmeCert.PrivateKey, acmeCert.Certificate)
		}

		certsFound[i].Acme = acmeClient
	}
	return certsFound
}

func getEnvOption(name string, required bool) string {
	val := os.Getenv(name)
	if required && len(val) == 0 {
		logrus.Fatalf("Required environment variable not set: %s", name)
	}
	return strings.TrimSpace(val)
}

func listToSlice(str string) []string {
	str = strings.ToLower(strings.Join(strings.Fields(str), ""))
	return strings.Split(str, ",")
}
