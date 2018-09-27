package rancher

import (
	"time"

	rancherClient "github.com/rancher/types/client/project/v3"
	"github.com/rancher/norman/clientbase"
)

type Client struct {
	client *rancherClient.Client
}

// NewClient returns a new client for the Rancher/Cattle API
func NewClient(rancherUrl string, rancherAccessKey string, rancherSecretKey string) (*Client, error) {

	opts := &clientbase.ClientOpts{
		URL:       rancherUrl,
		AccessKey: rancherAccessKey,
		SecretKey: rancherSecretKey,
		Timeout:   time.Second * 5,
	}

	var err error
	var apiClient *rancherClient.Client
	maxTime := 10 * time.Second

	for i := 1 * time.Second; i < maxTime; i *= time.Duration(2) {
		apiClient, err = rancherClient.NewClient(opts)
		if err == nil {
			break
		}
		time.Sleep(i)
	}

	if err != nil {
		return nil, err
	}

	return &Client{apiClient}, nil
}
