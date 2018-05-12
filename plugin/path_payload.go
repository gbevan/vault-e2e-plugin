package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"
	vapi "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/pluginutil"
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

var scs = spew.ConfigState{
	MaxDepth: 2,
}

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
	log.Println("**** in pathPayloadCreate ***") //" req:" + req.GoString())
	log.Println(scs.Sdump(ctx, req, data))

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

	apiClientMeta := &pluginutil.APIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:]) // Ignore command, strictly parse flags
	log.Printf("apiClientMeta: %s\n", scs.Sdump(apiClientMeta))

	tlsConfig := apiClientMeta.GetTLSConfig()
	log.Printf("tls: %s\n", scs.Sdump(tlsConfig))

	log.Printf("logical.Connection: %s\n", (&logical.Connection{}).RemoteAddr)

	clientConf := vapi.DefaultConfig()
	log.Printf("clientConf: %s\n", scs.Sdump(clientConf))
	client, err := vapi.NewClient(nil)
	// TODO: use current client token and address of unix domain socket instead
	client.SetToken("root")
	log.Printf("client: %s, err: %s\n", scs.Sdump(client), err)

	l := client.Logical()
	log.Printf("logical: %s\n", scs.Sdump(l))

	// Populate kv references back into payload structure
	// (note needs to walk nested maps/arrays, see
	// https://stackoverflow.com/questions/29366038/looping-iterate-over-the-second-level-nested-json-in-go-lang)
	for k, v := range payload {
		log.Println("k: " + k)
		if strings.Contains(k, "@/") {
			log.Printf("%s: matches for vault path\n", k)
			if v == true {
				log.Printf("%s: is true\n", k)
				parts := strings.SplitN(k, "@/", 2)
				log.Printf("%s\n", parts[0])
				log.Printf("%s\n", parts[1])
				fieldName := parts[0]
				secretPath := parts[1]

				s, err := l.Read(secretPath)
				log.Printf("secret: %s, err: %s\n", scs.Sdump(s), err)
				log.Printf("secret Data: %s\n", scs.Sdump(s.Data))

				d := s.Data["data"].(map[string]interface{})
				log.Printf("data: %s\n", scs.Sdump(d))
				payload[fieldName] = d["mydata"]
				// TODO: Support nested path expansion requests in payload
			}
		}
	}

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
