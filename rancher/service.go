package rancher

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	rancherClient "github.com/rancher/go-rancher/v2"
)

// GetServiceById retrieves an existing Service by ID
func (r *Client) GetServiceById(serviceId string) (*rancherClient.Service, error) {
	rancherService, err := r.client.Service.ById(serviceId)
	if err != nil {
		return nil, err
	}

	if rancherService == nil {
		return nil, fmt.Errorf("No such service with ID %s", serviceId)
	}

	logrus.Debugf("Got Rancher service %s by ID %s", rancherService.Name, serviceId)
	return rancherService, nil
}

func (r *Client) FindActiveServices() ([]rancherClient.Service, error) {
    var results []rancherClient.Service

	logrus.Info("Looking up stacks with labels")

	services, err := r.client.Service.List(&rancherClient.ListOpts{
		Filters: map[string]interface{}{
			"state": "active",
		},
	})
	if err != nil {
		return results, err
	}
	if len(services.Data) == 0 {
		logrus.Info("Did not find any active services")
		return results, nil
	}

	logrus.Debugf("Found %d active services", len(services.Data))

	for _, service := range services.Data {
		results = append(results, service)
	}

    return results, nil
}

func (r *Client) FilterServicesByLabel(services []rancherClient.Service, label string) ([]rancherClient.Service) {
	var results []rancherClient.Service
	for _, service := range services {
		for key, val := range service.LaunchConfig.Labels {
			if key == label {
				logrus.Debugf("%s has %s = %s", service.Name, label, val)
				results = append(results, service)
			}
		}
	}
	return results
}
