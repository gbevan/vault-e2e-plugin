#!/bin/sh
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
