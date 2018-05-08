package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

/*
 * Generate a new 2048 bit RSA key pair to Stdout
 */
func main() {
	// log.Println("**** Generating RSA key pair ****")
	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	checkError(err)

	publicKey := key.PublicKey

	// print PEM encoded private key
	privateKey := &pem.Block{
		Type:  fmt.Sprintf("RSA[%d] PRIVATE KEY", bitSize),
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	pem.Encode(os.Stdout, privateKey)

	// print PEM encoded public key
	asn1Bytes, err := asn1.Marshal(publicKey)
	checkError(err)

	pubKey := &pem.Block{
		Type:  fmt.Sprintf("RSA[%d] PUBLIC KEY", bitSize),
		Bytes: asn1Bytes,
	}
	pem.Encode(os.Stdout, pubKey)
}

func checkError(err error) {
	if err != nil {
		log.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}
