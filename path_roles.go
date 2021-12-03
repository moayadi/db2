package secretsengine

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)


const (
	staticRolePath = "static-role/"
)


// hashiCupsRoleEntry defines the data required
// for a Vault role to access and call the HashiCups
// token endpoints
type hashiCupsRoleEntry struct {
	Username string        `json:"username"`
	TTL      time.Duration `json:"ttl"`
	PasswordPolicy string `json:"password_policy,omitempty"`
	PasswordLength int `json:"length,omitempty"`
	SeedPassword string `json:"seed_password"`
	CurrentPassword string `json:"current_password"`
	NewPassword string `json:"new_password"`
	// LastVaultRotation represents the last time Vault rotated the password
	LastVaultRotation time.Time `json:"last_vault_rotation"`

	// RotationPeriod is number in seconds between each rotation, effectively a
	// "time to live". This value is compared to the LastVaultRotation to
	// determine if a password needs to be rotated
	RotationPeriod time.Duration `json:"rotation_period"`
}

// toResponseData returns response data for a role
func (r *hashiCupsRoleEntry) toResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		"ttl":      r.TTL.Seconds(),
		"username": r.Username,
		"password_policy": r.PasswordPolicy,
		"seed_password": r.SeedPassword,
		"new_password": r.NewPassword,
		"current_password": r.CurrentPassword,
		"rotation_period":     r.RotationPeriod.Seconds(),
		"last_vault_rotation": r.LastVaultRotation,

	}
	return respData
}

// pathRole extends the Vault API with a `/role`
// endpoint for the backend. You can choose whether
// or not certain attributes should be displayed,
// required, and named. You can also define different
// path patterns to list all roles.
func pathRole(b *hashiCupsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: staticRolePath + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
				"username": {
					Type:        framework.TypeString,
					Description: "The username for the HashiCups product API",
					Required:    true,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease for generated credentials. If not set or set to 0, will use system default.",
				},
				"password_policy": {
					Type:        framework.TypeString,
					Description: "The URL for the HashiCups Product API",
					Required:    true,
				},
				"seed_password": {
					Type:        framework.TypeString,
					Description: "Initial password for DB2 user",
					Required:    true,
				},
			},
			ExistenceCheck: b.pathRoleExistanceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRolesRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
				},
			},
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: staticRolePath + "?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
				},
			},
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

func (b *hashiCupsBackend) pathRoleExistanceCheck(ctx context.Context, request *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := b.staticRole(ctx, request.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}


func (b *hashiCupsBackend) staticRole(ctx context.Context, s logical.Storage, roleName string) (*hashiCupsRoleEntry,error) {
	entry, err := s.Get(ctx, staticRolePath+roleName)
	if err != nil {
		println(err.Error())
		return nil, err
	}
	if entry == nil {
		return nil, err
	}

	var result hashiCupsRoleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}



// pathRolesList makes a request to Vault storage to retrieve a list of roles for the backend
func (b *hashiCupsBackend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, staticRolePath)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// pathRolesRead makes a request to Vault storage to read a role and return response data
func (b *hashiCupsBackend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := b.getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: entry.toResponseData(),
	}, nil
}

// pathRolesWrite makes a request to Vault storage to update a role based on the attributes passed to the role configuration
func (b *hashiCupsBackend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing role name"), nil
	}


	roleEntry, err := b.getRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if roleEntry == nil {
		roleEntry = &hashiCupsRoleEntry{}
	}

	createOperation := (req.Operation == logical.CreateOperation)

	if username, ok := d.GetOk("username"); ok {
		roleEntry.Username = username.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing username in role")
	}

	if seedpassword, ok := d.GetOk("seed_password"); ok {
		roleEntry.SeedPassword = seedpassword.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing seed password")
	}

	if passwordPolicy, ok := d.GetOk("password_policy"); ok {
		roleEntry.PasswordPolicy = passwordPolicy.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing password policy")
	}

	if ttlRaw, ok := d.GetOk("ttl"); ok {
		roleEntry.TTL = time.Duration(ttlRaw.(int)) * time.Second
	} else if createOperation {
		roleEntry.TTL = time.Duration(d.Get("ttl").(int)) * time.Second
	}

	if err := setRole(ctx, req.Storage, name.(string), roleEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathRolesDelete makes a request to Vault storage to delete a role
func (b *hashiCupsBackend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, staticRolePath+d.Get("name").(string))
	if err != nil {
		return nil, fmt.Errorf("error deleting hashiCups role: %w", err)
	}

	return nil, nil
}

// setRole adds the role to the Vault storage API
func setRole(ctx context.Context, s logical.Storage, name string, roleEntry *hashiCupsRoleEntry) error {
	entry, err := logical.StorageEntryJSON(staticRolePath+name, roleEntry)
	if err != nil {
		return err
	}

	if entry == nil {
		return fmt.Errorf("failed to create storage entry for role")
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

// getRole gets the role from the Vault storage API
func (b *hashiCupsBackend) getRole(ctx context.Context, s logical.Storage, name string) (*hashiCupsRoleEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := s.Get(ctx, staticRolePath+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var role hashiCupsRoleEntry

	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

type roleEntry struct {
	StaticAccount *staticAccount `json:"static_account" mapstructure:"static_account"`
}

type staticAccount struct {

	// Username to create or assume management for static accounts
	Username string `json:"username"`

	// Password is the current password for static accounts. As an input, this is
	// used/required when trying to assume management of an existing static
	// account. Return this on credential request if it exists.
	Password string `json:"password"`

	// LastVaultRotation represents the last time Vault rotated the password
	LastVaultRotation time.Time `json:"last_vault_rotation"`

	// RotationPeriod is number in seconds between each rotation, effectively a
	// "time to live". This value is compared to the LastVaultRotation to
	// determine if a password needs to be rotated
	RotationPeriod time.Duration `json:"rotation_period"`
}

const (
	pathRoleHelpSynopsis    = `Manages the Vault role for generating HashiCups tokens.`
	pathRoleHelpDescription = `
This path allows you to read and write roles used to generate HashiCups tokens.
You can configure a role to manage a user's token by setting the username field.
`

	pathRoleListHelpSynopsis    = `List the existing roles in HashiCups backend`
	pathRoleListHelpDescription = `Roles will be listed by the role name.`
)

