package e2e

import (
	"context"
	"log"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// E2eBackend E2E Backend
type E2eBackend struct { // nolint
	*framework.Backend
	view logical.Storage
}

// Factory returns a new backend as logical.Backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(ctx, conf)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend export the function to create backend and configure
func Backend(ctx context.Context, conf *logical.BackendConfig) *E2eBackend {
	backend := &E2eBackend{
		view: conf.StorageView,
	}

	log.Println("**** E2E in Backend ****")

	backend.Backend = &framework.Backend{
		Help:        "E2E Plugin",
		BackendType: logical.TypeLogical,
		//		AuthRenew:   backend.pathAuthRenew,
		// PathsSpecial: &logical.Paths{
		// 	Unauthenticated: []string{
		// 		"jwt/validate/*",
		// 		"jwks/*",
		// 		"roles/jwks/*",
		// 	},
		// 	SealWrapStorage: []string{
		// 		"keys/",
		// 	},
		// },
		// Secrets: []*framework.Secret{
		// 	secretJWT(backend),
		// },
		Secrets: []*framework.Secret{
			&framework.Secret{
				Type: "kv",
			},
		},
		Paths: framework.PathAppend(
			pathEnrole(backend),
			pathPayload(backend),
		),
		WALRollback: rollback,
	}

	return backend
}

func rollback(context.Context, *logical.Request, string, interface{}) error {
	log.Println("in rollback")
	return nil
}
