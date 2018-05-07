package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// basic schema for the creation of the E2E enrolement,
// this will map the fields coming in from the vault request field map
var createE2eEncroleSchema = map[string]*framework.FieldSchema{

	"name": {
		Type:        framework.TypeString,
		Description: "The name of the e2e target endpoint being enrolled",
	},
	"pubkey": {
		Type:        framework.TypeString,
		Description: "End point's RSA Public Key",
	},
	"fingerprint": {
		Type:        framework.TypeString,
		Description: "RSA Public Key's fingerprint",
	},
	"authorised": {
		Type:        framework.TypeBool,
		Description: "Authorised status of this enrolement",
	},
	"created": {
		Type:        framework.TypeString,
		Description: "Datetime stamp then this enrolement was created",
	},
}

const e2eEnroleHelpDescription = `
E2E Enrolement Help goes here...
`

func pathEnrole(backend *E2eBackend) []*framework.Path {
	log.Println("**** in pathEnrole ***")
	paths := []*framework.Path{
		&framework.Path{
			Pattern:         fmt.Sprintf("enrole/"),
			HelpSynopsis:    "E2E Enrolements",
			HelpDescription: e2eEnroleHelpDescription,
			Fields:          createE2eEncroleSchema,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: backend.pathEnroleList,
			},
		},
		&framework.Path{
			Pattern:         fmt.Sprintf("enrole/%s", framework.GenericNameRegex("name")),
			HelpSynopsis:    "E2E Enrolements",
			HelpDescription: e2eEnroleHelpDescription,
			Fields:          createE2eEncroleSchema,
			ExistenceCheck:  backend.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: backend.pathEnroleCreate,
				logical.UpdateOperation: backend.pathEnroleDeny,
				logical.DeleteOperation: backend.pathEnroleDeny,
				logical.ReadOperation:   backend.pathEnroleRead,
				logical.ListOperation:   backend.pathEnroleList,
			},
		},
	}
	return paths
}

func (backend *E2eBackend) pathExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	log.Println("**** in pathExistenceCheck *** Path:" + req.Path)
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	return out != nil, nil
}

func (backend *E2eBackend) pathEnroleDeny(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Println("**** in pathEnroleDeny ***")

	response := logical.ErrorResponse("Denied - add only supported, updates/deletes require manual intervention for enrolement")
	return response, nil
}

func (backend *E2eBackend) pathEnroleCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Println("**** in pathEnroleCreate *** req:" + req.GoString())

	timeText, err := time.Now().MarshalText()
	if err != nil {
		return nil, err
	}

	enroleEntry := E2eEnrolementEntry{
		Name:        data.Get("name").(string),
		PubKey:      data.Get("pubkey").(string),
		Fingerprint: "Pubkey-finger-print-goes-here",
		Authorised:  false,
		Created:     string(timeText),
	}

	dataJSON, err := json.Marshal(enroleEntry)
	if err != nil {
		return nil, err
	}

	entry := &logical.StorageEntry{
		Key:   req.Path,
		Value: []byte(dataJSON),
	}

	s := req.Storage
	err = s.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	body := fmt.Sprintf("{\"Name\": \"%s\"}", enroleEntry.Name)
	log.Println("body: " + body)

	response := &logical.Response{
		Data: map[string]interface{}{
			"Name": enroleEntry.Name,
		},
	}

	return response, nil
}

func (backend *E2eBackend) pathEnroleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Println("**** in pathEnroleRead ***")

	entry, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	jsonValue := entry.Value

	backend.Logger().Info("reading value", "key", req.Path, "json", string(jsonValue))

	// unmarshal the json encoded data
	var enrole E2eEnrolementEntry
	err = json.Unmarshal(jsonValue, &enrole)
	if err != nil {
		return nil, err
	}

	// Return the secret
	resp := &logical.Response{
		Data: map[string]interface{}{
			"key":    req.Path,
			"enrole": enrole,
		},
	}
	return resp, nil
}

func (backend *E2eBackend) pathEnroleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Println("**** in pathEnroleList ***")

	entries, err := req.Storage.List(ctx, req.Path)
	if err != nil {
		return nil, err
	}

	var list []string
	for _, ent := range entries {
		list = append(list, ent)
	}

	return logical.ListResponse(list), nil
}
