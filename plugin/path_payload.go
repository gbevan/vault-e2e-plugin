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
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
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
	"payload": {
		Type:        framework.TypeMap,
		Description: "Payload structure (JSON encoded) to request secret interpolation and encrypting for target endpoint",
	},
}

const e2ePayloadHelpDescription = `
E2E Payload Help goes here...
`

var scs = spew.ConfigState{
	MaxDepth: 2,
}

func pathPayload(backend *E2eBackend) []*framework.Path {
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
	return false, nil
}

func (backend *E2eBackend) pathPayloadCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// payload to populate from kv and encrypt with public key
	payload := data.Get("payload").(map[string]interface{})
	name := "enrole/" + strings.TrimLeft(req.Path, "payload/")

	entry, err := req.Storage.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	jsonValue := entry.Value

	// unmarshal the json encoded data
	var enrole E2eEnrolementEntry
	err = json.Unmarshal(jsonValue, &enrole)
	if err != nil {
		return nil, err
	}

	// decode PEM public key
	// https://golang.org/pkg/encoding/pem/#Decode
	pblock, _ := pem.Decode([]byte(enrole.PubKey))
	if pblock == nil || pblock.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(pblock.Bytes)
	if err != nil {
		return nil, err
	}

	// populate payload with nested kv secrets
	errors := []string{}
	errorCount := 0
	err = populate(ctx, req, payload, &errorCount, &errors)
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
	if err != nil {
		return nil, err
	}

	// see https://golang.org/pkg/crypto/cipher/#example_NewGCM_encrypt
	// AES encrypt payload using key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate nonce/iv
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt AESGCM and Seal
	ciphertext := aesgcm.Seal(nil, nonce, sPayload, nil)

	// encrypt the above key using RSA public key
	// https://golang.org/pkg/crypto/rsa/#EncryptOAEP
	label := []byte("Vault E2E Payload")
	rng := rand.Reader
	keyNonce := key
	keyNonce = append(keyNonce, nonce...)

	RSACiphertext, err := rsa.EncryptOAEP(sha256.New(), rng, pub.(*rsa.PublicKey), []byte(keyNonce), label)
	if err != nil {
		return nil, err
	}

	// Since encryption is a randomized function, ciphertext will be
	// different each time.

	// combine RSA with AEs cipher bytes
	combined := make([]byte, 2)
	binary.LittleEndian.PutUint16(combined, uint16(len(RSACiphertext)))
	combined = append(combined, RSACiphertext...)
	combined = append(combined, ciphertext...)

	// Wrap in Armor
	armourLines := []string{
		"-----BEGIN E2E ENCRYPTED PAYLOAD-----",
		"PAYLOAD_VERSION: 2.0",
		"",
	}
	armourLines = append(
		armourLines,
		splitB64(
			string(
				base64.StdEncoding.EncodeToString(combined)),
			76,
		)...,
	)
	armourLines = append(
		armourLines,
		"-----END E2E ENCRYPTED PAYLOAD-----",
	)

	// Return the Encrypted payload
	resp := &logical.Response{
		Data: map[string]interface{}{
			"payload":    strings.Join(armourLines, "\n"),
			"errorcount": errorCount,
			"errors":     errors,
		},
	}
	return resp, nil
}

// Populate kv references back into payload structure
// (note needs to walk nested maps/arrays, see
// https://stackoverflow.com/questions/29366038/looping-iterate-over-the-second-level-nested-json-in-go-lang)
func populate(ctx context.Context, req *logical.Request, payload interface{}, errorCount *int, errors *[]string) error {
	reflectPayload := reflect.ValueOf(payload)
	p := reflectPayload
	if reflectPayload.Type().Kind() == reflect.Struct {
		p = reflect.ValueOf(structs.Map(payload))
	}
	for _, key := range p.MapKeys() {
		k := key.String()
		v := payload.(map[string]interface{})[k]

		tv := reflect.ValueOf(v).Kind()
		if tv == reflect.Map || tv == reflect.Struct {
			err := populate(ctx, req, v, errorCount, errors)
			if err != nil {
				return err
			}
			continue
		}

		if strings.Contains(k, "@/") {
			if v == true {
				parts := strings.SplitN(k, "@/e2e/", 2)
				fieldName := parts[0]
				secretPathExp := parts[1]

				secParts := strings.SplitN(secretPathExp, ".", 2)

				if len(secParts) < 2 {
					payloadError(payload, k, fmt.Sprintf("Error: Parsing variable at path (.part) from request"), errorCount, errors)
					continue
				}

				s, err := req.Storage.Get(ctx, secParts[0])
				if err != nil {
					payloadError(payload, k, fmt.Sprintf("Error: in storage get request: %s", err), errorCount, errors)
					continue
				}
				if s != nil {
					vData := map[string]interface{}{}
					if err := json.Unmarshal(s.Value, &vData); err != nil {
						payloadError(payload, k, fmt.Sprintf("Error: unmarshalling json: %s", err), errorCount, errors)
						continue
					}

					accessor := fmt.Sprintf(".%s", secParts[1])
					tmpl, err := template.New("eval").Parse(fmt.Sprintf("{{%s}}", accessor))
					if err != nil {
						payloadError(payload, k, fmt.Sprintf("Error: in template parse: %s", err), errorCount, errors)
						continue
					}

					var b bytes.Buffer
					err = tmpl.Execute(&b, &vData)
					if err != nil {
						payloadError(payload, k, fmt.Sprintf("Error: in template execute: %s", err), errorCount, errors)
						continue
					}
					if b.String() == "" {
						payloadError(payload, k, "Error: template interpolation resolved to an empty string", errorCount, errors)
						continue
					}

					payload.(map[string]interface{})[fieldName] = b.String()
					delete(payload.(map[string]interface{}), k)
				} else {
					payloadError(payload, k, "Error: path not found", errorCount, errors)
				}
			}
		}
	} //for
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

func payloadError(payload interface{}, key string, errmsg string, errorCount *int, errors *[]string) {
	log.Println(errmsg)
	payload.(map[string]interface{})[key] = errmsg
	*errorCount++
	*errors = append(*errors, fmt.Sprintf("%3d) `%s`: %s", *errorCount, key, errmsg))
}
