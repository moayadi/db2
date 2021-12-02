package secretsengine

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const staticRolePath = "role"
// pathCredentials extends the Vault API with a `/creds`
// endpoint for a role. You can choose whether
// or not certain attributes should be displayed,
// required, and named.
func pathCredentials(b *hashiCupsBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},

		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathCredentialsRead,
			logical.UpdateOperation: b.pathCredentialsRead,
		},
		HelpSynopsis:    pathCredentialsHelpSyn,
		HelpDescription: pathCredentialsHelpDesc,
	}
}

// pathCredentialsRead creates a new HashiCups token each time it is called if a
// role exists.
func (b *hashiCupsBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	roleEntry, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}


	return b.createUserCreds(ctx, req, roleEntry, roleName)
}

// createUserCreds creates a new HashiCups token to store into the Vault backend, generates
// a response with the secrets information, and checks the TTL and MaxTTL attributes.
func (b *hashiCupsBackend) createUserCreds(ctx context.Context, req *logical.Request, role *hashiCupsRoleEntry, roleName string) (*logical.Response, error) {
	token, err := b.createToken(ctx, req.Storage, role)
	if err != nil {
		return nil, err
	}

	if role.CurrentPassword == "" {
		role.CurrentPassword = role.SeedPassword
		println("mycurrentrole is " + role.CurrentPassword)
		newpassword, _ := b.generatePassword(ctx, role)
		role.NewPassword = newpassword
		println("now it is " + role.NewPassword)
	}else if role.CurrentPassword != "" {
		println("moayad is here")
		role.CurrentPassword = role.NewPassword
		newpassword, _ := b.generatePassword(ctx, role)
		role.NewPassword = newpassword
	}

	entry, err := logical.StorageEntryJSON(staticRolePath+roleName, role)
	//if err != nil {
	//	return output, err
	//}
	if err := req.Storage.Put(ctx, entry); err != nil {
		println("success adding secrets back")
	}





	// The response is divided into two objects (1) internal data and (2) data.
	// If you want to reference any information in your code, you need to
	// store it in internal data!
	resp := b.Secret(hashiCupsTokenType).Response(map[string]interface{}{
		"token":        token.Token,
		"token_id":     token.TokenID,
		"user_id":      token.UserID,
		"username":     token.Username,
		"new_password": role.NewPassword,
		"current_password": role.CurrentPassword,
		"seed_password" : role.SeedPassword,
	}, map[string]interface{}{
		"token":         token.Token,
		"new_password" : role.NewPassword,
		"seed_password" : role.SeedPassword,
		"current_password": role.CurrentPassword,
	})

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}

	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}

// createToken uses the HashiCups client to sign in and get a new token
func (b *hashiCupsBackend) createToken(ctx context.Context, s logical.Storage, roleEntry *hashiCupsRoleEntry) (*hashiCupsToken, error) {
	client, err := b.getClient(ctx, s)
	if err != nil {
		return nil, err
	}

	var token *hashiCupsToken

	token, err = createToken(ctx, client, roleEntry.Username)
	if err != nil {
		return nil, fmt.Errorf("error creating HashiCups token: %w", err)
	}

	if token == nil {
		return nil, errors.New("error creating HashiCups token")
	}

	return token, nil
}

const pathCredentialsHelpSyn = `
Generate a HashiCups API token from a specific Vault role.
`

const pathCredentialsHelpDesc = `
This path generates a HashiCups API user tokens
based on a particular role. A role can only represent a user token,
since HashiCups doesn't have other types of tokens.
`
