package secretsengine

import (
	"context"
	//"github.com/hashicorp/errwrap"

	"errors"
	"fmt"
	//"math"
	"time"

	//"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/vault/sdk/framework"
	//"github.com/hashicorp/vault/sdk/helper/consts"
	//"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	//"github.com/hashicorp/vault/sdk/queue"
)

const (
	rotateRootPath = "rotate-root"
	rotateRolePath = "rotate-cred/"
)

func pathRotateCredentials(b *hashiCupsBackend) *framework.Path {
	return &framework.Path{
			Pattern: rotateRolePath + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the static role",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback:                    b.pathRotateRoleCredentialsUpdate,
					ForwardPerformanceStandby:   true,
					ForwardPerformanceSecondary: true,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback:                    b.pathRotateRoleCredentialsUpdate,
					ForwardPerformanceStandby:   true,
					ForwardPerformanceSecondary: true,
				},
			},
			HelpSynopsis:    "Request to rotate the credentials for a static user account.",
			HelpDescription: "This path attempts to rotate the credentials for the given OpenLDAP static user account.",

	}
}

func (b *hashiCupsBackend) pathRotateRoleCredentialsUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("empty role name attribute given"), nil
	}

	role, err := b.staticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role doesn't exist: %s", name), nil
	}


	input := &setStaticAccountInput{
		RoleName: name,
		Role:     role,
	}
	resp, err := b.setStaticAccountPassword(ctx, req.Storage, input)
	if err != nil {
		b.Logger().Warn("unable to rotate credentials in rotate-role", "error", err)
	}

	// We're not returning creds here because we do not know if its been processed
	// by the queue.
	return resp, nil
}

type setStaticAccountInput struct {
	RoleName string
	Role     *hashiCupsRoleEntry
}

type setStaticAccountOutput struct {
}


func (b *hashiCupsBackend) setStaticAccountPassword(ctx context.Context, s logical.Storage, input *setStaticAccountInput) (*logical.Response, error) {
	if input == nil || input.Role == nil || input.RoleName == "" {
		return nil, errors.New("input was empty when attempting to set credentials for static account")
	}

	b.lock.Lock()
	defer b.lock.Unlock()

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errors.New("the config is currently unset")
	}

	role, err := b.staticRole(ctx, s, input.RoleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, errors.New("role doesn't exist")
	}

	var newPassword string

	if role.CurrentPassword == "" {
		input.Role.CurrentPassword = input.Role.SeedPassword
		newPassword, _ := b.GeneratePassword(ctx, role)
		input.Role.NewPassword = newPassword
		println("now it is " + role.NewPassword)
	}else if role.CurrentPassword != "" {
		input.Role.CurrentPassword = role.NewPassword
		newPassword, _ := b.GeneratePassword(ctx, role)
		input.Role.NewPassword = newPassword
	}

	//newPassword, err = b.GeneratePassword(ctx, role)

	// Update the password remotely.
	//if err := b.client.UpdatePassword(config.LDAP, input.Role.StaticAccount.DN, newPassword); err != nil {
	//	return output, err
	//}

	// Store updated role information
	// lvr is the known LastVaultRotation
	lvr := time.Now()
	input.Role.LastVaultRotation = lvr
	input.Role.CurrentPassword = input.Role.NewPassword
	input.Role.NewPassword = newPassword
	//output.RotationTime = lvr

	entry, err := logical.StorageEntryJSON(staticRolePath+input.RoleName, input.Role)
	if err != nil {
		return nil, err
	}
	if err := s.Put(ctx, entry); err != nil {
		return nil, err
	}


	return &logical.Response{
	Data: map[string]interface{}{
	"username":            role.Username,
	"current_password":    input.Role.CurrentPassword,
	"new_password":    	   newPassword,
	"ttl":                 input.Role.TTL,
	"rotation_period":     input.Role.RotationPeriod.Seconds(),
	"last_vault_rotation": input.Role.LastVaultRotation,
	},
	}, nil

	}

func (b *hashiCupsBackend) GeneratePassword(ctx context.Context, role *hashiCupsRoleEntry) (string, error) {
	if role.PasswordPolicy == "" {
		if role.PasswordLength == 0 {
			return base62.Random(defaultPasswordLength)
		}
		return base62.Random(role.PasswordLength)
	}

	password, err := b.System().GeneratePasswordFromPolicy(ctx, role.PasswordPolicy)
	if err != nil {
		return "", fmt.Errorf("unable to generate password: %w", err)
	}
	return password, nil
}