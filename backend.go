package db2secretengine

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// db2Backend defines an object that
// extends the Vault backend and stores the
// target API's client.
type db2Backend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *db2Client
	//store map[string][]byte
}

// backend defines the target API backend
// for Vault. It must include each path
// and the secrets it will store.
func backend() *db2Backend {
	var b = db2Backend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
		Paths: framework.PathAppend(
			pathRole(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathCredentials(&b),
				pathRotateCredentials(&b),
			},
		),
		Secrets: []*framework.Secret{},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}
	return &b
}

// reset clears any client configuration for a new
// backend to be configured
func (b *db2Backend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

// invalidate clears an existing client configuration in
// the backend
func (b *db2Backend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

// getClient locks the backend as it configures and creates a
// a new client for the target API
func (b *db2Backend) getClient(ctx context.Context, s logical.Storage) (*db2Client, error) {

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = new(db2Config)
	}

	b.client, err = newClient(config)
	if err != nil {
		return nil, err
	}

	return b.client, nil
}


// backendHelp should contain help information for the backend
const backendHelp = `
The DB2 secrets backend provides the ability to rotate passwords of existing DB2 users.
After mounting this backend, credentials for existing DB2 users 
must be configured with the "config/" endpoints.
`
