#!/bin/sh -xe
# wait for vault to start
until $(vault status | grep "Cluster ID" > /dev/null); do
  >&2 echo "Vault is unavailable - sleepy time"
  sleep 1
done

>&2 echo "Vault ready - carry on"

export VURL="http://127.0.0.1:${VAULT_PORT}/v1"

cd test/bats
chmod 755 *.sh
for b in *.sh
do
  ./$b
done
