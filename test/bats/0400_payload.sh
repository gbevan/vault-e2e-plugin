#!/usr/bin/env bats

@test "can request a payload to be populated with secrets an encrypted" {
  curl -s -H "Accept: application/json" \
    -H "Content-type: application/json" \
    --header "X-Vault-Token: root" \
    $VURL/e2e/payload/BATS1 -X POST \
    --data '{"payload": {"hello": "world", "secretData@/e2e/kv/my-secret.mydata": true, "nested": {"anotherSecret@/e2e/kv/my-secret2.mydata2": true, "nested_level3": {"OMG_REALLY_SECRET@/e2e/kv/my-secret3.mydata3": true}, "array": [{"OMG_REALLY_SECRET_SERIOUSLY@/e2e/kv/my-secret3.mydata3": true}]}}}'
}

@test "populate a form with secrets and encrypt" {
  PAYLOAD=$(curl -s -H "Accept: application/json" \
    -H "Content-type: application/json" \
    --header "X-Vault-Token: root" \
    $VURL/e2e/payload/BATS1 -X POST \
    --data @../form1.json | jq -r .data.payload)

  echo "$PAYLOAD" > ../payload.txt

  [ "$PAYLOAD" != "" ]
}

@test "can decrypt the payload using private key" {
  PAYLOAD=$(cat ../payload.txt)
  echo -e "PAYLOAD:\n$PAYLOAD"
  ls -la ..
  FORM=$(echo "$PAYLOAD" | /vault/plugins/decrypt -privkey ../bats_rsa.pem)

  [ "$FORM" != "" ]
}
