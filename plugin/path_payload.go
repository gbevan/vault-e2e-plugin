package e2e

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log"
	"os"
	"reflect"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/fatih/structs"
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

	// decode PEM public key
	// https://golang.org/pkg/encoding/pem/#Decode
	pblock, rest := pem.Decode([]byte(enrole.PubKey))
	log.Printf("pBlock: %s, rest: %s\n", pblock, rest)
	if pblock == nil || pblock.Type != "PUBLIC KEY" {
		log.Fatal("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(pblock.Bytes)
	// var pub *rsa.PublicKey
	// rest, err := asn1.Unmarshal(pub, pblock.Bytes)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	log.Printf("Got a %T, with remaining data: %q", pub, rest)

	// populate payload with nested kv secrets
	err = populate(ctx, req, payload)
	if err != nil {
		return nil, err
	}

	// Generate random key
	key, err := generateRandomBytes(32)
	if err != nil {
		return nil, err
	}

	// Stringify payload
	sPayload, err := json.Marshal(payload)
	log.Printf("sPayload: %s\n", sPayload)

	// see https://golang.org/pkg/crypto/cipher/#example_NewGCM_encrypt

	// AES encrypt payload using key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	// Generate nonce/iv
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	// Encrypt AESGCM and Seal
	ciphertext := aesgcm.Seal(nil, nonce, sPayload, nil)
	log.Printf("AES ciphertext: %x\n", ciphertext)

	// encrypt the above key using RSA public key
	// https://golang.org/pkg/crypto/rsa/#EncryptOAEP
	// keyB64 := base64.StdEncoding.EncodeToString(key)
	// log.Printf("keyB64: %s\n", keyB64)
	label := []byte("My Payload...")
	rng := rand.Reader
	keyNonce := key
	keyNonce = append(keyNonce, nonce...)

	RSACiphertext, err := rsa.EncryptOAEP(sha256.New(), rng, pub.(*rsa.PublicKey), []byte(keyNonce), label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
		panic(err.Error())
	}

	// Since encryption is a randomized function, ciphertext will be
	// different each time.
	log.Printf("RSA Ciphertext: %x\n", RSACiphertext)

	// Wrap in Armor
	armourLines := []string{
		"PAYLOAD_VERSION: 2.0",
		"-----BEGIN RSA ENCRYPTED PAYLOAD (1)-----",
		string(base64.StdEncoding.EncodeToString(RSACiphertext)),
		"-----END RSA ENCRYPTED PAYLOAD (1)-----",
		"-----BEGIN AES-256 ENCRYPTED PAYLOAD (2)-----",
	}

	armourLines = append(
		armourLines,
		splitB64(
			string(
				base64.StdEncoding.EncodeToString(ciphertext)),
			76,
		)...,
	)
	armourLines = append(armourLines, "-----END AES-256 ENCRYPTED PAYLOAD (2)-----")

	log.Println(strings.Join(armourLines, "\n"))

	// Return the Encrypted payload
	resp := &logical.Response{
		Data: map[string]interface{}{
			"key":               req.Path,
			"enrole":            enrole,
			"orig_payload":      payload,
			"marshaled_payload": sPayload,
			"payload":           strings.Join(armourLines, "\n"),
		},
	}
	log.Println("return")
	return resp, nil
}

// Populate kv references back into payload structure
// (note needs to walk nested maps/arrays, see
// https://stackoverflow.com/questions/29366038/looping-iterate-over-the-second-level-nested-json-in-go-lang)
func populate(ctx context.Context, req *logical.Request, payload interface{}) error {
	log.Println("*************** POPULATE ****************")
	// k := map[string]interface{}{}
	// v := map[string]interface{}{}
	reflectPayload := reflect.ValueOf(payload)
	p := reflectPayload
	if reflectPayload.Type().Kind() == reflect.Struct {
		p = reflect.ValueOf(structs.Map(payload))
	}
	for _, key := range p.MapKeys() {
		log.Printf("key: %s\n", key)
		// v := reflectPayload.MapIndex(key)
		k := key.String()
		v := payload.(map[string]interface{})[k]
		log.Printf("v: %s\n", v)
		log.Printf("v type: %s\n", reflect.TypeOf(v))
		log.Printf("v type kind: %s\n", reflect.TypeOf(v).Kind())

		tv := reflect.ValueOf(v).Kind()
		log.Printf("tv: %s\n", tv)
		if tv == reflect.Map || tv == reflect.Struct {
			err := populate(ctx, req, v)
			if err != nil {
				return err
			}
			continue
		}

		if strings.Contains(k, "@/") {
			log.Printf("%s: matches for vault path\n", k)
			if v == true {
				log.Printf("%s: is true\n", k)
				// parts := strings.SplitN(k, "@/", 2)
				parts := strings.SplitN(k, "@/e2e/", 2)
				log.Printf("%s\n", parts[0])
				log.Printf("%s\n", parts[1])
				fieldName := parts[0]
				secretPathExp := parts[1]

				secParts := strings.SplitN(secretPathExp, ".", 2)
				log.Printf("secParts: %s\n", secParts)

				// secretPath := parts[1]

				// s, err := l.Read(secretPath)
				s, err := req.Storage.Get(ctx, secParts[0])
				if err != nil {
					log.Println(err)
				}
				if s != nil {
					log.Printf("secret: %s, err: %s\n", scs.Sdump(s), err)
					// log.Printf("secret Data: %s\n", scs.Sdump(s.Data))
					log.Printf("secret Data: %s\n", scs.Sdump(s.Value))

					// d := s.Data["data"].(map[string]interface{})
					// d := s.Data //.(map[string]interface{}
					// d := s.Value
					vData := map[string]interface{}{}
					if err := json.Unmarshal(s.Value, &vData); err != nil {
						return err
					}
					log.Printf("data: %s\n", scs.Sdump(vData))

					accessor := fmt.Sprintf(".%s", secParts[1])
					log.Printf("accessor: %s\n", accessor)
					//
					// expr, err := govaluate.NewEvaluableExpression(accessor)
					// if err != nil {
					// 	log.Println(err)
					// }
					// parms := make(map[string]interface{}, 8)
					// parms["vData"] = vData
					// exprRes, err := expr.Evaluate(parms)
					// if err != nil {
					// 	log.Println(err)
					// }
					// log.Printf("exprRes: %s\n", exprRes)

					tmpl, err := template.New("eval").Parse(fmt.Sprintf("{{%s}}", accessor))
					if err != nil {
						log.Println(err)
					}
					// log.Printf("tmpl: %s\n", tmpl)

					var b bytes.Buffer
					err = tmpl.Execute(&b, &vData)
					if err != nil {
						log.Println(err)
					}
					log.Printf("b: %s\n", b.String())

					// payload[fieldName] = vData["mydata"]
					//*payload.(*map[string]interface{}
					payload.(map[string]interface{})[fieldName] = b.String()
					// TODO: Support nested path expansion requests in payload

				}
			}
		}
	} //for
	log.Println("-------------- POPULATE --------------")
	return nil
}

// from https://blog.questionable.services/article/generating-secure-random-numbers-crypto-rand/
// MIT licensed
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// https://stackoverflow.com/questions/45412089/split-a-base64-line-into-chunks
func splitB64(s string, size int) []string {
	ss := make([]string, 0, len(s)/size+1)
	for len(s) > 0 {
		if len(s) < size {
			size = len(s)
		}
		ss, s = append(ss, s[:size]), s[size:]
	}
	return ss
}
