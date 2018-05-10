package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// basic schema for the submission of payload encryption requests,
// this will map the fields coming in from the vault request field map
var createE2ePayloadSchema = map[string]*framework.FieldSchema{
	// "name": {
	// 	Type:        framework.TypeString,
	// 	Description: "The name of the e2e target endpoint the payload is to be delivered to",
	// },
	"payload": {
		Type:        framework.TypeMap,
		Description: "Payload structure (JSON encoded) to request populating and encrypting for target endpoint",
	},
}

const e2ePayloadHelpDescription = `
E2E Payload Help goes here...
`

func pathPayload(backend *E2eBackend) []*framework.Path {
	log.Println("**** in pathPayload ***")
	paths := []*framework.Path{
		&framework.Path{
			Pattern:      fmt.Sprintf("payload/"),
			HelpSynopsis: "E2E Encrypted Payload Request API",
			// HelpDescription: e2eEnroleHelpDescription,
			Fields:    createE2ePayloadSchema,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				// logical.ListOperation: backend.pathEnroleList,
			},
		},
		&framework.Path{
			Pattern:      fmt.Sprintf("payload/%s", framework.GenericNameRegex("name")),
			HelpSynopsis: "E2E Encrypted Payload Request API",
			//HelpDescription: e2eEnroleHelpDescription,
			Fields:         createE2ePayloadSchema,
			ExistenceCheck: backend.dummyNotExists,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: backend.pathPayloadCreate,
				// logical.UpdateOperation: backend.pathEnroleDeny,
				// logical.DeleteOperation: backend.pathEnroleDeny,
				// logical.ReadOperation:   backend.pathEnroleRead,
				// logical.ListOperation:   backend.pathEnroleList,
			},
		},
	}
	return paths
}

func (backend *E2eBackend) dummyNotExists(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	log.Println("**** in dummyNotExists *** Path:" + req.Path)
	return false, nil
}

func (backend *E2eBackend) pathPayloadCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Println("**** in pathPayloadCreate *** req:" + req.GoString())

	// payload to populate from kv and encrypt with public key
	payload := data.Get("payload").(map[string]interface{})
	// log.Println("payload: " + payload)

	name := "enrole/" + strings.TrimLeft(req.Path, "payload/")
	log.Println("NAME: " + name)

	entry, err := req.Storage.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	log.Println("after get")

	if entry == nil {
		return nil, nil
	}
	log.Println("after nil test")

	jsonValue := entry.Value

	backend.Logger().Info("reading value", "key", req.Path, "json", string(jsonValue))

	// unmarshal the json encoded data
	var enrole E2eEnrolementEntry
	err = json.Unmarshal(jsonValue, &enrole)
	if err != nil {
		return nil, err
	}
	log.Println("after unmarshal")

	// Populate kv references back into payload structure

	// Generate random key/iv

	// Stringify and encrypt payload using key/iv and AWS256GCM

	// Binary-ify key/iv and encrypt using RSA public key

	// Wrap in Armor

	// Return the Encrypted payload
	resp := &logical.Response{
		Data: map[string]interface{}{
			"key":     req.Path,
			"enrole":  enrole,
			"payload": payload,
		},
	}
	log.Println("return")
	return resp, nil
}
