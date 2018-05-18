package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"log"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// refs:
//    https://github.com/hashicorp/vault/blob/master/logical/plugin/mock/path_kv.go
//    https://github.com/hashicorp/vault-plugin-secrets-kv/blob/master/path_data.go
func pathKV(backend *E2eBackend) []*framework.Path {
	log.Println("**** in pathKV ***")
	paths := []*framework.Path{
		// &framework.Path{
		// 	Pattern:      fmt.Sprintf("kv/"),
		// 	HelpSynopsis: "E2E Encrypted KV Request API",
		// 	// HelpDescription: e2eEnroleHelpDescription,
		// 	Fields:    createE2eKVSchema,
		// 	Callbacks: map[logical.Operation]framework.OperationFunc{
		// 		// logical.ListOperation: backend.pathEnroleList,
		// 	},
		// },
		&framework.Path{
			Pattern:      "kv/.*",
			HelpSynopsis: "E2E Encrypted KV Request API",
			//HelpDescription: e2eEnroleHelpDescription,
			Fields: map[string]*framework.FieldSchema{
				"data": {
					Type:        framework.TypeMap,
					Description: "The contents of the data map will be stored and returned on read.",
				},
			},
			ExistenceCheck: backend.kvExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: backend.pathKVWrite,
				logical.UpdateOperation: backend.pathKVWrite,
				logical.DeleteOperation: backend.pathKVDelete,
				logical.ReadOperation:   backend.pathKVRead,
				logical.ListOperation:   backend.pathKVList,
			},
		},
	}
	return paths
}

func (backend *E2eBackend) kvExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	log.Println("**** in kvExistenceCheck *** Path:" + req.Path)
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	return out != nil, nil
}

func (backend *E2eBackend) pathKVWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Println("**** in pathKVCreate *** req:" + req.GoString())

	key := req.Path
	log.Printf("key: %s", key)

	var marshaledData []byte
	// {
	dataRaw, ok := data.GetOk("data")
	if !ok {
		return logical.ErrorResponse("no data provided"), logical.ErrInvalidRequest
	}
	marshaledData, err := json.Marshal(dataRaw.(map[string]interface{}))
	if err != nil {
		return nil, err
	}
	// }
	log.Printf("marshaledData: %s", marshaledData)

	err = req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   key,
		Value: marshaledData,
	})
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"value": dataRaw,
		},
	}, nil
}

func (backend *E2eBackend) pathKVDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Println("**** in pathKVDelete *** req:" + req.GoString())

	if err := req.Storage.Delete(ctx, req.Path); err != nil {
		return nil, err
	}

	return nil, nil
}

func (backend *E2eBackend) pathKVRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Println("**** in pathKVRead *** req:" + req.GoString())

	entry, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, errors.New("could not find version data")
	}

	log.Printf("entry: %s", entry.Value)

	vData := map[string]interface{}{}
	if err := json.Unmarshal(entry.Value, &vData); err != nil {
		return nil, err
	}

	// resp.Data["data"] = vData

	return &logical.Response{
		Data: vData,
	}, nil
}

func (backend *E2eBackend) pathKVList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Println("**** in pathKVList *** req:" + req.GoString())

	vals, err := req.Storage.List(ctx, "kv/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(vals), nil
}
