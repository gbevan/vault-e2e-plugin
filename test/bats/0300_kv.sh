#!/usr/bin/env bats

@test "can add secrets" {
  curl -s -H "Accept: application/json" \
    -H "Content-type: application/json" \
    --header "X-Vault-Token: root"  \
    $VURL/e2e/kv/my-secret -X POST \
    --data '{"data": {"mydata": "This is a secret!"}}' && \
  curl -s -H "Accept: application/json" \
    -H "Content-type: application/json" \
    --header "X-Vault-Token: root"  \
    $VURL/e2e/kv/my-secret2 -X POST \
    --data '{"data": {"mydata2": "This is another secret!"}}' && \
  curl -s -H "Accept: application/json" \
    -H "Content-type: application/json" \
    --header "X-Vault-Token: root" \
    $VURL/e2e/kv/my-secret3 -X POST \
    --data '{"data": {"mydata3": "THIS IS A REALLY SECRET SECRET!!! ARRAYS NEED MORE THOUGHT IN populate()..."}}' && \
  curl -s -H "Accept: application/json" \
    -H "Content-type: application/json" \
    --header "X-Vault-Token: root"  \
    $VURL/e2e/kv/Customer1/Actor1/secret-form -X POST \
    --data @../secrets.json
}

@test "can retrieve secrets" {
  curl -s -H "Accept: application/json" \
    -H "Content-type: application/json" \
    --header "X-Vault-Token: root" \
    --request GET $VURL/e2e/kv/my-secret && \
  curl -s -H "Accept: application/json" \
    -H "Content-type: application/json" \
    --header "X-Vault-Token: root" \
    --request GET $VURL/e2e/kv/my-secret2 && \
  curl -s -H "Accept: application/json" \
    -H "Content-type: application/json" \
    --header "X-Vault-Token: root" \
    --request GET $VURL/e2e/kv/my-secret3 && \
  curl -s -H "Accept: application/json" \
    -H "Content-type: application/json" \
    --header "X-Vault-Token: root" \
    --request GET $VURL/e2e/kv/Customer1/Actor1/secret-formX
}
