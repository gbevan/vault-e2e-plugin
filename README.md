# Hashicorp Vault End-to-End Encryption Plugin

A proof-of-concept plugin for Hashicorp Vault to provide end-to-end encryption of
secret interpolated JSON payloads using RSA-2048 and AES256GCM.

Allows for the enrolement of a receipient's RSA public key, and use of this key
to encrypt JSON encoded payloads which can only be decrypted using the
recipient's RSA private key.

This plugin was written for educational purposes while learning the Go
language (golang) and Hashicorp Vault.

## Secret Interpolation
The plugin only supports kv secrets under it's own `/e2e/` mount point.
A json payload can request these secrets to be interpolated into the payload,
e.g.:
```
{
  "payload": {
    "level1": {
      "level2": {
        "level3": {
          "level4": {
            "level5": {
              "field1@/e2e/kv/Customer1/Actor1/secret-form.secret1": true,
              "field2@/e2e/kv/Customer1/Actor1/secret-form.secret2": true
            }
          }
        }
      },
      "fromdeep@/e2e/kv/Customer1/Actor1/secret-form.nested.level2.deepsecret": true,
      "missing_novar@/e2e/kv/Customer1/Actor1/secret-form.willnotbefound": true,
      "missing_nopath@/e2e/kv/Customer1/Actor1/nopath.willnotbefound": true
    }
  }
}
```
keys like `fieldname@/e2e/pathto/secret.nested.field.value` can be encoded and
this will resolve to the field nested within the json encoded secret.
The value is then included in the returned encrypted payload as `"fieldname": "value"`.

The api returns:
```
{
  "request_id": "480a6c54-e23f-a04e-547e-80aa048753be",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "errorcount": 2,
    "errors": [
      "  1) `missing_nopath@/e2e/kv/Customer1/Actor1/nopath.willnotbefound`: Error: path not found",
      "  2) `missing_novar@/e2e/kv/Customer1/Actor1/secret-form.willnotbefound`: Error: template interpolation resolved to an empty string"
    ],
    "payload": "-----BEGIN E2E ENCRYPTED PAYLOAD-----\nPAYLOAD_VERSION: 2.0\n\nAAE376QDTo8griCitf74dyy3v+NT+tANOK4vVduQKS1rnPKmZrw57WwpoaWtyMwhDz/zwen18BLT\ndyDHer2eWTKlY58NLCfOnUZUlv5mAGmGOeL9omKNl+92Rg0X8NDycJQ1UgMdyMi3jjcfTuS0M+Nh\nPQeYvnOfeKHjp4lvetZRmqPLTzLAfi7QoL0zT0UBrG3dZYYoS/RQQUW08ZdQ2noheqDAXn3ocSHM\n7ZgBKKBRYbeJrVAdxYkZ97ogMmspfzzLlWWKstCCfiTdsjqhGTiUOnMf17QD+/bKGU1ndUQWOLcF\nA8bBHZAygLd5dRlbbFpiyAWYG3d51011GoA7dKLcSBX4qA1LavwuiJx93KYWnCQU4zV6IAWPPuvo\nYpeHgncaPSq5bq7OKT2IrYFem5oBfhmiC7FvAPHYCQaYx+JZMLTn3P53+7J1WqiCJET9bI/Cd3rY\nVL7OEJxYcg3oKAPSlSasByfv/JoNO9VwMcmpoff5ORjJm8q2haNlDbyQjof5Xy+YQDDuC46NS4oX\nj14fsXh7YmRx8eAnXhHg0zFAO42EKCok+cGDi/GuaO7myDadkLQ8A1qoflYgo50Uybe+jaQZPheK\nU+i/khbZfHKy96c4Pv1Kp21wF86My55fMH/P0iXmrbHoQculJdKseOo4pyF+xjZHG5HKkRF8LVA2\nwvyZ98Fj9TuShfmLm5xfonCjJS6Ot2mLye2XMiGhdXMmSvx4JSqpa8dX5NtHv/DkdXZ/qySEmZ1J\nckmlpnBffC9Yyr7Qm0s89exf0TP5YKHnY84uR538fhc5j5E07P+MT4OyaL8O78H1z0XJ2UJ46Thn\nPY8I1yN1dQy79Q==\n-----END E2E ENCRYPTED PAYLOAD-----"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```
payload:
```
-----BEGIN E2E ENCRYPTED PAYLOAD-----
PAYLOAD_VERSION: 2.0

AAE376QDTo8griCitf74dyy3v+NT+tANOK4vVduQKS1rnPKmZrw57WwpoaWtyMwhDz/zwen18BLT
dyDHer2eWTKlY58NLCfOnUZUlv5mAGmGOeL9omKNl+92Rg0X8NDycJQ1UgMdyMi3jjcfTuS0M+Nh
PQeYvnOfeKHjp4lvetZRmqPLTzLAfi7QoL0zT0UBrG3dZYYoS/RQQUW08ZdQ2noheqDAXn3ocSHM
7ZgBKKBRYbeJrVAdxYkZ97ogMmspfzzLlWWKstCCfiTdsjqhGTiUOnMf17QD+/bKGU1ndUQWOLcF
A8bBHZAygLd5dRlbbFpiyAWYG3d51011GoA7dKLcSBX4qA1LavwuiJx93KYWnCQU4zV6IAWPPuvo
YpeHgncaPSq5bq7OKT2IrYFem5oBfhmiC7FvAPHYCQaYx+JZMLTn3P53+7J1WqiCJET9bI/Cd3rY
VL7OEJxYcg3oKAPSlSasByfv/JoNO9VwMcmpoff5ORjJm8q2haNlDbyQjof5Xy+YQDDuC46NS4oX
j14fsXh7YmRx8eAnXhHg0zFAO42EKCok+cGDi/GuaO7myDadkLQ8A1qoflYgo50Uybe+jaQZPheK
U+i/khbZfHKy96c4Pv1Kp21wF86My55fMH/P0iXmrbHoQculJdKseOo4pyF+xjZHG5HKkRF8LVA2
wvyZ98Fj9TuShfmLm5xfonCjJS6Ot2mLye2XMiGhdXMmSvx4JSqpa8dX5NtHv/DkdXZ/qySEmZ1J
ckmlpnBffC9Yyr7Qm0s89exf0TP5YKHnY84uR538fhc5j5E07P+MT4OyaL8O78H1z0XJ2UJ46Thn
PY8I1yN1dQy79Q==
-----END E2E ENCRYPTED PAYLOAD-----
```
The `payload` can then be sent to the recipient to be decrypted with their
RSA private key.

## Testing
Run ./docker.sh to build the test docker conatiner and run the tests.
See contents of the `test/` folder for the tests and example curl commands.

## Decrypting
A go program to decrypt the payload is available called `test/decrypt.go`.
To run:
```
vault-e2e-plugin/test$ go run decrypt.go -privkey test_key_rsa.pem <payload.txt |jq
{
  "level1": {
    "fromdeep": "this is a deep secret",
    "level2": {
      "level3": {
        "level4": {
          "level5": {
            "field1": "this is secret 1",
            "field2": "this is secret 2"
          }
        }
      }
    },
    "missing_nopath@/e2e/kv/Customer1/Actor1/nopath.willnotbefound": "Error: path not found",
    "missing_novar@/e2e/kv/Customer1/Actor1/secret-form.willnotbefound": "Error: template interpolation resolved to an empty string"
  }
}
```

## Notes
```
vault write sys/plugins/catalog/e2e \
    sha_256=7db215b0a08eaae0bb111084ff598bd8f44b1faef85b230d7e1f8fa27096eff8 \
    command="vault-e2e-plugin"

vault secrets enable -path=e2e -plugin-name=e2e plugin
```

## Generate a RSA Key Pair (for testing)

```
go run bin/genrsapair.go [-prefix test/test_key]
```
to generate PEM key pair to stdout
```
go run bin/genrsapair.go &&  jq -Rsc . < test/test_key_rsa_pub.pem >test/test_key_rsa_pub_string.pem
```
to encode as json string array, that can be pasted into a curl command for
enrolement.
```
curl -s -H "Accept: application/json" \
  -H "Content-type: application/json" \
  --header "X-Vault-Token: root" \
  --request POST http://127.0.0.1:8210/v1/e2e/enrole/TEST \
  --data '{"name": "TEST", "pubkey":"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbz8uJeyqUMfZe+dHYcq\nAtQOtCjCzztLgPLNH/i+oQvlfiWZfmBtbYeEHVEPyd0O1hLM7cS3nUbY9JgHQQyC\nYnVvGcz9/BrPzCksVqr6lyFM2/6hjkUqJv47xwVaaW464hwRB0dEDCxwJUtM4gIa\nD4gwAfiHlU5BGRyDq0Cl0pwniN4othA12PZsFgM4F96MfpsLO5jNFmVcfjyFAq6k\nEdYPjfHRgZmdkbOhlDLyx6FknE8L68QcANcQw3olGizgIW2MTdwCOuWk3oeohBvz\nA0uYO6GdRxL1IIzOcy+IJqmhjbua6utwgOiiNQs7cxil4CEsmveYZ0Q8n18B+rIJ\niQIDAQAB\n-----END PUBLIC KEY-----\n"}'
```
Check the enrolement entry in Vault E2E:
```
curl -s -H "Accept: application/json" \
  -H "Content-type: application/json" \
  --header "X-Vault-Token: root" \
  http://127.0.0.1:8210/v1/e2e/enrole/TEST \
  -X GET | jq
```
```json
{
  "request_id": "bc9f7b56-a22c-a80e-adec-f683ddb29bde",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "enrole": {
      "authorised": false,
      "created": "2018-05-09T20:15:18.59043786Z",
      "fingerprint": "Pubkey-finger-print-goes-here",
      "name": "TEST",
      "pubkey": "-----BEGIN RSA[2048] PUBLIC KEY-----\nMIIBCgKCAQEAykQ6BB4ayKtzvQBoswbxOPaxblag6OMZ9an0ASMvkGAAkaIvkYUe\nfVwNoeixWZsdFr7q8IVOonVWFBMCf5TFKm8GWN2HNnlePL5/GH3QOWYkbCBciF2D\nEv9hiMRzoT9NmTH1m29x7sDfNTIndp2LGKTPLReGr866iPu7Res88chQQ+AC//wG\n9Wqe9Xzlg4tCJd2TY36Ia6K2P0QTahp9hCha2U9pplzJZM37MpNhMqCHOxGuCLkL\nPKy/F82AJ24+iHYLJnpDU0TVFjPoYTMKYh9R36bVl6yURPTIsW/CvYAYE9VBm5KS\n6v5MZIfHqs16qq1AIVHZnfsXKDbmfBZEOwIDAQAB\n-----END RSA[2048] PUBLIC KEY-----\n"
    },
    "key": "enrole/TEST"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```
