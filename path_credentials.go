package db2secretengine

import (
	"context"
	//"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"time"
	//"errors"
)

const (
	staticCredPath = "static-cred/"
)


// pathCredentials extends the Vault API with a `/creds`
// endpoint for a role. You can choose whether
// or not certain attributes should be displayed,
// required, and named.
func pathCredentials(b *db2Backend) *framework.Path {
	return &framework.Path{
		Pattern: staticCredPath + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},

		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathCredentialsRead,
		},
		HelpSynopsis:    pathCredentialsHelpSyn,
		HelpDescription: pathCredentialsHelpDesc,
	}
}

// pathCredentialsRead wil return the current role details including the current password used by the database user

func (b *db2Backend) pathCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name := d.Get("name").(string)

	role, err := b.staticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("unknown role: %s", name), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"username":            role.Username,
			"current_password":    role.CurrentPassword,
			"ttl":                 role.TTL,
			"rotation_period":     role.RotationPeriod.Seconds(),
			"last_vault_rotation": role.LastVaultRotation,
		},
	}, nil
}



func (s *staticAccount) PasswordTTL() time.Duration {
	next := s.NextRotationTime()
	ttl := next.Sub(time.Now()).Round(time.Second)
	if ttl < 0 {
		ttl = time.Duration(0)
	}
	return ttl
}

func (s *staticAccount) NextRotationTime() time.Time {
	return s.LastVaultRotation.Add(s.RotationPeriod)
}

const pathCredentialsHelpSyn = `
Read DB2 Role details including current DB2 user credentials.
`

const pathCredentialsHelpDesc = `
to be updated
`
