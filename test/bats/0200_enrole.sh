#!/usr/bin/env bats

@test "can generate rsa key pair" {
  pwd
  ls -la /vault/plugins/genrsapair
  /vault/plugins/genrsapair -prefix ../bats
}

@test "rsa priv key exist in test folder" {
  ls -la ../
  [ -e ../bats_rsa.pem ]
}

@test "rsa pub key exist in test folder" {
  ls -la ../
  [ -e ../bats_rsa_pub.pem ]
}

@test "can post public key to enrole in vault e2e plugin" {
  PUBKEY=$(jq -Rsc . < ../bats_rsa_pub.pem)
  echo "$PUBKEY"
  curl -s -H "Accept: application/json" \
    -H "Content-type: application/json" \
    --header "X-Vault-Token: root" \
    --request POST $VURL/e2e/enrole/BATS1 \
    --data "{\"name\": \"BATS1\", \"pubkey\":$PUBKEY}"
}

@test "can get enroled public key from vault path" {
  PUBKEY=$(cat ../bats_rsa_pub.pem)

  ENROLEDKEY=$(curl -s -H "Accept: application/json" \
    -H "Content-type: application/json" \
    --header "X-Vault-Token: root" \
    --request GET $VURL/e2e/enrole/BATS1 | jq -r .data.enrole.pubkey)

  echo "PUBKEY: $PUBKEY"
  echo "ENROLEDKEY: $ENROLEDKEY"
  [ "$ENROLEDKEY" = "$PUBKEY" ]
}
