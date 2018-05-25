#!/usr/bin/env bats

@test "can install the e2e plugin" {
  vault write sys/plugins/catalog/e2e-plugin sha_256=$(cat /vault/plugins/e2e-plugin.sha) command=e2e-plugin
}

@test "can enable the e2e plugin" {
  vault secrets enable --plugin-name=e2e-plugin --description="e2e encryption" --path="e2e" plugin
}
