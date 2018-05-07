# Hashicorp Vault End-to-End Encryption Plugin

vault write sys/plugins/catalog/e2e \
    sha_256=7db215b0a08eaae0bb111084ff598bd8f44b1faef85b230d7e1f8fa27096eff8 \
    command="vault-e2e-plugin"

vault secrets enable -path=e2e -plugin-name=e2e plugin
