package secretsengine

import (
	"errors"

	db2client "vault-plugin-secrets-hashicups/db2client"
	//hashicups "github.com/hashicorp-demoapp/hashicups-client-go"
)

// hashiCupsClient creates an object storing
// the client.
type hashiCupsClient struct {
	*db2client.Client
}

// newClient creates a new client to access HashiCups
// and exposes it for any secrets or roles to use.
func newClient(config *hashiCupsConfig) (*hashiCupsClient, error) {
	if config == nil {
		return nil, errors.New("client configuration was nil")
	}

	//if config.Username == "" {
	//	return nil, errors.New("client username was not defined")
	//}
	//
	//if config.Password == "" {
	//	return nil, errors.New("client password was not defined")
	//}
	//
	//if config.URL == "" {
	//	return nil, errors.New("client URL was not defined")
	//}

	c, err := db2client.NewClient(&config.Hostname, &config.Port)
	if err != nil {
		return nil, err
	}
	return &hashiCupsClient{c}, nil
	//return &hashiCupsClient{nil}, nil
}
