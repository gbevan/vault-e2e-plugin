package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
)

/*
 * Generate a new 2048 bit RSA key pair to Stdout
 */
func main() {
	prefix := flag.String("prefix", "test/test_key", "folder/file prefix to generate key pair to")
	flag.Parse()

	privKeyFilename := fmt.Sprintf("%s_rsa.pem", *prefix)
	pubKeyFilename := fmt.Sprintf("%s_rsa_pub.pem", *prefix)

	privKeyFile, err := os.OpenFile(privKeyFilename, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}

	pubKeyFile, err := os.OpenFile(pubKeyFilename, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		panic(err)
	}

	// log.Println("**** Generating RSA key pair ****")
	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	checkError(err)

	key.Precompute()
	// http://golang.org/pkg/crypto/rsa/#PrivateKey.Validate
	err = key.Validate()
	checkError(err)

	publicKey := &key.PublicKey

	// print PEM encoded private key
	privateKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	pem.Encode(privKeyFile, privateKey)
	if err = privKeyFile.Close(); err != nil {
		panic(err)
	}

	fmt.Println()

	// print PEM encoded public key
	// asn1Bytes, err := asn1.Marshal(publicKey)
	pkixBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	checkError(err)

	pubKey := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkixBytes,
	}
	pem.Encode(pubKeyFile, pubKey)
	if err := pubKeyFile.Close(); err != nil {
		panic(err)
	}
}

func checkError(err error) {
	if err != nil {
		log.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}
