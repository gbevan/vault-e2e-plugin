package main

import (
	"log"
	"os"

	"github.com/SermoDigital/jose/jws"
	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/pluginutil"
	"github.com/hashicorp/vault/logical/plugin"
	e2e "gitlab.com/gbevan/vault-e2e-plugin/plugin"
)

var E2eVaultAddress = ""
var E2eVaultToken = ""

func main() {
	log.Println("**** E2E plugin main.go entered ****")
	E2eVaultAddress = os.Getenv(api.EnvVaultAddress)
	log.Printf("E2eVaultAddress: %s\n", E2eVaultAddress)
	E2eVaultToken = os.Getenv(api.EnvVaultToken)
	log.Printf("E2eVaultToken: %s\n", E2eVaultToken)

	unwrapToken := os.Getenv(pluginutil.PluginUnwrapTokenEnv)
	log.Printf("PluginUnwrapTokenEnv: %s\n", unwrapToken)
	wt, err := jws.ParseJWT([]byte(unwrapToken))
	log.Printf("wt: %s, err: %s\n", spew.Sdump(wt), err)

	log.Printf("Env: %s\n", os.Environ())

	apiClientMeta := &pluginutil.APIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:]) // Ignore command, strictly parse flags

	tlsConfig := apiClientMeta.GetTLSConfig()
	log.Printf("tlsConfig: %s\n", spew.Sdump(tlsConfig))
	tlsProviderFunc := pluginutil.VaultPluginTLSProvider(tlsConfig)

	factoryFunc := e2e.Factory

	// Fail the version check, falling back to netRPC
	// os.Unsetenv("VAULT_VERSION")

	err = plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: factoryFunc,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
