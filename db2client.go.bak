package secretsengine

import (
	"errors"
	db2 "vault-plugin-secrets-hashicups/db2client"
)

// hashiCupsClient creates an object storing
// the client.
type db2Client struct {
	*db2.Client
}

// newClient creates a new client to access HashiCups
// and exposes it for any secrets or roles to use.
func newDb2Client(config *hashiCupsConfig) (*db2Client, error) {
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

	c, err := db2.NewClient(&config.Hostname, &config.Port)
	if err != nil {
		return nil, err
	}
	return &db2Client{c}, nil
	//return &db2Client{nil}, nil
}
