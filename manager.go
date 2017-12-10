package main

import (
	// "os"
	"strings"
	"time"
	"github.com/Sirupsen/logrus"
)

func (c *Context) Run() {
	if c.RunOnce {
		// Renew certificate if it's about to expire
		c.renew()
		logrus.Info("Run once: Finished")
		return
	}

	for {
		<-c.timer()
		c.renew()
	}
}


func (c *Context) GatherCertificates() {
	activeServices, err := c.Rancher.FindActiveServices()
	if err != nil {
		logrus.Infof("%v", err)
		return
	}

	labelledServices := c.Rancher.FilterServicesByLabel(activeServices, c.ServiceLabel)
	if err != nil {
		logrus.Infof("%v", err)
		return
	}

	for _, service := range labelledServices {
		labelValue := service.LaunchConfig.Labels[c.ServiceLabel].(string)
		certsFound := c.BuildCertificatesFromServiceLabel(labelValue)
		for i, _ := range certsFound {
			c.Certificates = append(c.Certificates, certsFound[i])
		}

		logrus.Infof("%v", c.Certificates)
	}
}

func (c *Context) renew() {
	c.GatherCertificates()
	for index, cert := range c.Certificates {
		logrus.Infof("Trying to obtain SSL certificate (%s: %s) from Let's Encrypt %s CA",
			cert.CommonName, strings.Join(cert.AltNames, ","), cert.Acme.ApiVersion())

		var success bool
		var newCert Certificate
		if cert.ExpiryDate.IsZero() {
			success, newCert = c.GetCertNew(cert)
		} else {
			success, newCert = c.GetCertRenewal(cert)
		}

		if success {
			logrus.Infof("Certificate managed successfully")
			err := c.Rancher.UpdateLoadBalancer(c.LoadBalancerName, newCert.RancherCertId)
			if err == nil {
				c.Certificates[index] = newCert
				logrus.Infof("Updated Load Balancer")
			} else {
				logrus.Fatalf("Failed to upgrade load balancers: %v", err)
			}
		}
	}
}

func (c *Context) GetCertNew(cert Certificate) (bool, Certificate) {
	if cert.Acme.ProviderName() == "HTTP" {
		logrus.Info("Using HTTP Challenge: " +
			"Make sure that HTTP requests for '/.well-known/acme-challenge' for all certificate " +
			"domains are forwarded to port 80 of the container running this application")
	}

	acmeCert, failures := cert.Acme.Issue(cert.CommonName, append([]string{cert.CommonName}, cert.AltNames...))
	if len(failures) > 0 {
		for k, v := range failures {
			logrus.Errorf("[%s] Error obtaining certificate: %s", k, v.Error())
		}
	} else {
		if cert.RancherCertId != "" {
			if c.updateRancherCert(cert.CommonName, cert.RancherCertId, acmeCert.PrivateKey, acmeCert.Certificate) {
				cert.ExpiryDate = acmeCert.ExpiryDate
				return true, cert
			}
		} else {
			newId := c.addRancherCert(cert.CommonName, acmeCert.PrivateKey, acmeCert.Certificate)
			if newId != "" {
				cert.RancherCertId = newId
				cert.ExpiryDate = acmeCert.ExpiryDate
				return true, cert
			}
		}
	}
	return false, cert
}

func (c *Context) GetCertRenewal(cert Certificate) (bool, Certificate) {
	if cert.Acme.ProviderName() == "HTTP" {
		logrus.Info("Using HTTP Challenge: " +
			"Make sure that HTTP requests for '/.well-known/acme-challenge' for all certificate " +
			"domains are forwarded to port 80 of the container running this application")
	}

	if time.Now().UTC().After(c.getRenewalDate(cert)) {
		acmeCert, err := cert.Acme.Renew(cert.CommonName)
		if err != nil {
			logrus.Errorf("Failed to renew certificate: %v", err)
		}
		cert.ExpiryDate = acmeCert.ExpiryDate
		logrus.Debugf("Overwriting Rancher certificate '%s'", cert.CommonName)

		if c.updateRancherCert(cert.CommonName, cert.RancherCertId, acmeCert.PrivateKey, acmeCert.Certificate) {
			return true, cert
		}
	}
	return false, cert
}

func (c *Context) addRancherCert(commonName string, privateKey []byte, cert []byte) string {
	rancherCert, err := c.Rancher.AddCertificate(commonName, CERT_DESCRIPTION, privateKey, cert)
	if err != nil {
		logrus.Fatalf("Failed to add Rancher certificate '%s': %v", commonName, err)
		return ""
	}
	logrus.Infof("Certificate '%s' added to Rancher", commonName)
	return rancherCert.Id
}

func (c *Context) updateRancherCert(commonName string, rancherCertId string, privateKey []byte, cert []byte) bool {
	err := c.Rancher.UpdateCertificate(rancherCertId, CERT_DESCRIPTION, privateKey, cert)
	if err != nil {
		logrus.Fatalf("Failed to update Rancher certificate '%s': %v", commonName, err)
		return false
	}
	logrus.Infof("Updated Rancher certificate '%s'", commonName)
	return true
}
//
func (c *Context) timer() <-chan time.Time {
	left := 120 * time.Second

	return time.After(left)
}
//
func (c *Context) getRenewalDate(cert Certificate) time.Time {
	if cert.ExpiryDate.IsZero() {
		logrus.Fatalf("Could not determine expiry date for certificate: %s", cert.CommonName)
	}
	date := cert.ExpiryDate.AddDate(0, 0, -c.RenewalPeriodDays)
	dYear, dMonth, dDay := date.Date()
	return time.Date(dYear, dMonth, dDay, c.RenewalDayTime, 0, 0, 0, time.UTC)
}

func (c *Context) parseServiceLabel(label string) []Certificate {
	// # i.e. TLD : CN : AN, AN ; TLD : CN.....
	// separate_certs = certstring.replace(' ', '').split(';')
	//
	// for certspec in separate_certs:
	// 	title_split = certspec.split(':')
	// 	alt_names = []
	//
	// 	if len(title_split) > 2:
	// 		alt_names = title_split[2:]
	//
	// 	self.cert_labels.append({'tld': title_split[0], 'common_name': title_split[1], 'alt_names': alt_names})
	var certsOut []Certificate
	separate_certs := strings.Split(label, ";")

	for _, certspec := range separate_certs {
		title_split := strings.Split(certspec, ":")
		var alt_names []string

		if len(title_split) > 3 {
			alt_names = title_split[3:]
		}

		certsOut = append(certsOut, Certificate{
			TLD: title_split[1],
			CommonName: title_split[2],
			AltNames: alt_names,
			KeyType: title_split[0],
		})
	}

	return certsOut
}
