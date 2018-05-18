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
curl -s -H "Accept: application/json" -H "Content-type: application/json" --header "X-Vault-Token: root" --request POST $VURL/e2e/enrole/TEST --data '{"name": "TEST", "pubkey":"-----BEGIN RSA[2048] PUBLIC KEY-----\nMIIBCgKCAQEAykQ6BB4ayKtzvQBoswbxOPaxblag6OMZ9an0ASMvkGAAkaIvkYUe\nfVwNoeixWZsdFr7q8IVOonVWFBMCf5TFKm8GWN2HNnlePL5/GH3QOWYkbCBciF2D\nEv9hiMRzoT9NmTH1m29x7sDfNTIndp2LGKTPLReGr866iPu7Res88chQQ+AC//wG\n9Wqe9Xzlg4tCJd2TY36Ia6K2P0QTahp9hCha2U9pplzJZM37MpNhMqCHOxGuCLkL\nPKy/F82AJ24+iHYLJnpDU0TVFjPoYTMKYh9R36bVl6yURPTIsW/CvYAYE9VBm5KS\n6v5MZIfHqs16qq1AIVHZnfsXKDbmfBZEOwIDAQAB\n-----END RSA[2048] PUBLIC KEY-----\n"}'

# Get payload using above key's path
curl -s -H "Accept: application/json" -H "Content-type: application/json" --header "X-Vault-Token: root"  $VURL/e2e/payload/TEST -X POST  --data '{"payload": {"hello": "world"}}' | jq .

# Add a secret in kv
# curl -s -H "Accept: application/json" -H "Content-type: text/plain" --header "X-Vault-Token: root"  $VURL/secret/my-secret-string -X POST --data '"This is a secret!"'

# curl -s -H "Accept: application/json" -H "Content-type: application/json" --header "X-Vault-Token: root"  $VURL/secret/data/my-secret -X POST --data '{"data": {"mydata": "This is a secret!"}}'
curl -s -H "Accept: application/json" -H "Content-type: application/json" --header "X-Vault-Token: root"  $VURL/e2e/kv/my-secret -X POST --data '{"data": {"mydata": "This is a secret!"}}'

# Get payload referencing above secret path
curl -s -H "Accept: application/json" -H "Content-type: application/json" --header "X-Vault-Token: root"  $VURL/e2e/payload/TEST -X POST  --data '{"payload": {"hello": "world", "secretData@/e2e/kv/my-secret": true}}' | jq .

vault secrets list
