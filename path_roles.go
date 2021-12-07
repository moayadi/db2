package db2secretengine

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

// db2RoleEntry defines all the db2 users that are to be managed in the designated db2 database.
type db2RoleEntry struct {
	Username string        `json:"username"`
	TTL      time.Duration `json:"ttl"`
	PasswordPolicy string `json:"password_policy,omitempty"`
	PasswordLength int `json:"length,omitempty"`
	Database string `json:"database"`
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
func (r *db2RoleEntry) toResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		"ttl":      r.TTL.Seconds(),
		"username": r.Username,
		"password_policy": r.PasswordPolicy,
		"database": r.Database,
		//"new_password": r.NewPassword,
		//"current_password": r.CurrentPassword,
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
func pathRole(b *db2Backend) []*framework.Path {
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
				"current_password": {
					Type:        framework.TypeString,
					Description: "Current password for DB2 user",
					Required:    true,
				},
				"database": {
					Type:        framework.TypeString,
					Description: "database to connect to for DB2 user",
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

func (b *db2Backend) pathRoleExistanceCheck(ctx context.Context, request *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := b.staticRole(ctx, request.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}


func (b *db2Backend) staticRole(ctx context.Context, s logical.Storage, roleName string) (*db2RoleEntry,error) {
	entry, err := s.Get(ctx, staticRolePath+roleName)
	if err != nil {
		println(err.Error())
		return nil, err
	}
	if entry == nil {
		return nil, err
	}

	var result db2RoleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}



// pathRolesList makes a request to Vault storage to retrieve a list of roles for the backend
func (b *db2Backend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, staticRolePath)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// pathRolesRead makes a request to Vault storage to read a role and return response data
func (b *db2Backend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
func (b *db2Backend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing role name"), nil
	}


	roleEntry, err := b.getRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if roleEntry == nil {
		roleEntry = &db2RoleEntry{}
	}

	createOperation := (req.Operation == logical.CreateOperation)

	if username, ok := d.GetOk("username"); ok {
		roleEntry.Username = username.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing username in role")
	}

	if currentPassword, ok := d.GetOk("current_password"); ok {
		roleEntry.CurrentPassword = currentPassword.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing current password")
	}

	if passwordPolicy, ok := d.GetOk("password_policy"); ok {
		roleEntry.PasswordPolicy = passwordPolicy.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing password policy")
	}

	if database, ok := d.GetOk("database"); ok {
		roleEntry.Database = database.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing database")
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
func (b *db2Backend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, staticRolePath+d.Get("name").(string))
	if err != nil {
		return nil, fmt.Errorf("error deleting hashiCups role: %w", err)
	}

	return nil, nil
}

// setRole adds the role to the Vault storage API
func setRole(ctx context.Context, s logical.Storage, name string, roleEntry *db2RoleEntry) error {
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
func (b *db2Backend) getRole(ctx context.Context, s logical.Storage, name string) (*db2RoleEntry, error) {
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

	var role db2RoleEntry

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
	pathRoleHelpSynopsis    = `Manages the Vault role for rotating DB2 user passwords`
	pathRoleHelpDescription = `
To be updated
`

	pathRoleListHelpSynopsis    = `List the existing roles in DB2 backend`
	pathRoleListHelpDescription = `Roles will be listed by the role name.`
)

