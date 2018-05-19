#!/bin/sh -xe
# wait for vault to start
until $(vault status | grep "Cluster ID" > /dev/null); do
  >&2 echo "Vault is unavailable - sleepy time"
  sleep 1
done

>&2 echo "Vault ready - carry on"

# set up vault
vault login root

# install the jwt plugin
vault write sys/plugins/catalog/e2e-plugin sha_256=$(cat /vault/plugins/e2e-plugin.sha) command=e2e-plugin

vault secrets enable --plugin-name=e2e-plugin --description="E2E Encryption" --path="e2e" plugin

echo "******************************************************************"
VURL="http://127.0.0.1:${VAULT_PORT}/v1"
# Enrole public key
curl -s -H "Accept: application/json" -H "Content-type: application/json" --header "X-Vault-Token: root" --request POST $VURL/e2e/enrole/TEST --data '{"name": "TEST", "pubkey":"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3DgpbGxfgGUVI4DwngZF\npPg9Z8ZJjAXgs9OhMHxfEo89Q+Jeo5aPYfWtBE+thFPAsjRdvm1gXeU14LKtIGHf\nh/aTeaapsxOG2AywMRs0+7SMndU1agz5HWfZ2FqBEuembq2HhQxprQexUqV0GoAm\n+lcGcllJeDZJoXwn9Kf7+HvAeEjWZqQKkj7I3UF6zQmMNgE0JArfAldV4LjoUqh5\nZoEod2yrdLsEU8+KQOFpZL8VN/F6EFEkjFXoTSV3iA4Cx+5IMhUPh5ZA2aU8Go6u\nmc40ZUWqNYTdeOQ3eOhMMdH7v/Sv+faDHok+gjheOxbEX0xAPaqaB6VO0DMqp3zO\nGwIDAQAB\n-----END PUBLIC KEY-----\n"}'

# Get payload using above key's path
# curl -s -H "Accept: application/json" -H "Content-type: application/json" --header "X-Vault-Token: root"  $VURL/e2e/payload/TEST -X POST  --data '{"payload": {"hello": "world"}}' | jq .

# Add a secret in kv
# curl -s -H "Accept: application/json" -H "Content-type: text/plain" --header "X-Vault-Token: root"  $VURL/secret/my-secret-string -X POST --data '"This is a secret!"'

# curl -s -H "Accept: application/json" -H "Content-type: application/json" --header "X-Vault-Token: root"  $VURL/secret/data/my-secret -X POST --data '{"data": {"mydata": "This is a secret!"}}'
curl -s -H "Accept: application/json" -H "Content-type: application/json" --header "X-Vault-Token: root"  $VURL/e2e/kv/my-secret -X POST --data '{"data": {"mydata": "This is a secret!"}}'
curl -s -H "Accept: application/json" -H "Content-type: application/json" --header "X-Vault-Token: root"  $VURL/e2e/kv/my-secret2 -X POST --data '{"data": {"mydata2": "This is another secret!"}}'

# Get payload referencing above secret path
curl -s -H "Accept: application/json" -H "Content-type: application/json" --header "X-Vault-Token: root"  $VURL/e2e/payload/TEST -X POST  --data '{"payload": {"hello": "world", "secretData@/e2e/kv/my-secret.mydata": true, "nested": {"anotherSecret@/e2e/kv/my-secret2.mydata2": true}}}' | jq .data.payload -r

vault secrets list
