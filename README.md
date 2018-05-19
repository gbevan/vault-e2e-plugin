# Hashicorp Vault End-to-End Encryption Plugin
```
vault write sys/plugins/catalog/e2e \
    sha_256=7db215b0a08eaae0bb111084ff598bd8f44b1faef85b230d7e1f8fa27096eff8 \
    command="vault-e2e-plugin"

vault secrets enable -path=e2e -plugin-name=e2e plugin
```

## Generate a RSA Key Pair (for testing)

```
go run bin/genrsapair.go
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
