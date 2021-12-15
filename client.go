package db2secretengine

import (
	"errors"

	"vault-plugin-secrets-hashicups/db2client"
)

// Db2Client creates an object storing
// the client.
type db2Client struct {
	*db2client.Client
}

// newClient creates a new client to access HashiCups
// and exposes it for any secrets or roles to use.
func newClient(config *db2Config) (*db2Client, error) {
	if config == nil {
		return nil, errors.New("client configuration was nil")
	}

	c, err := db2client.NewClient(&config.Hostname, &config.Port)
	if err != nil {
		return nil, err
	}
	return &db2Client{c}, nil

}
