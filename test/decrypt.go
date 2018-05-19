package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func main() {
	privkeyFile := flag.String("privkey", "", "private key file")
	flag.Parse()

	keyPem, err := ioutil.ReadFile(*privkeyFile)
	if err != nil {
		panic(err)
	}
	keyPKCS1, _ := pem.Decode(keyPem)
	// fmt.Printf("key keyPKCS1: %s\n", spew.Sdump(keyPKCS1))
	// fmt.Printf("key rest: %s\n", rest)

	key, err := x509.ParsePKCS1PrivateKey(keyPKCS1.Bytes)
	if err != nil {
		panic(err)
	}
	// fmt.Printf("privkey: %s\n", spew.Sdump(*key))

	// read payload from stdin
	scanner := bufio.NewScanner(os.Stdin)
	stage := "payloadversion"

	// break out sections
	rsaPayloadB64 := ""
	aesPayloadB64 := ""
	// payloadVersion := ""
	for scanner.Scan() {
		line := scanner.Text()
		switch stage {
		case "payloadversion":
			// fmt.Printf("> %s\n", line)
			// parts := strings.SplitN(line, ": ", 2)
			// payloadVersion = parts[1]
			stage = "rsa"
		case "rsa":
			if !strings.HasPrefix(line, "-----") {
				rsaPayloadB64 += strings.Trim(line, "")
			} else if strings.HasPrefix(line, "-----END") {
				stage = "aes"
			}
		case "aes":
			if !strings.HasPrefix(line, "-----") {
				aesPayloadB64 += strings.Trim(line, "")
			} else if strings.HasPrefix(line, "-----END") {
				break
			}
		default:
			panic("invalid state at line: " + line)
		}
	}
	// fmt.Printf("payloadVersion: %s\n", payloadVersion)
	// fmt.Printf("rsaPayloadB64: %s\n", rsaPayloadB64)
	// fmt.Printf("aesPayloadB64: %s\n", aesPayloadB64)

	rsaPayload, err := base64.StdEncoding.DecodeString(rsaPayloadB64)
	if err != nil {
		panic(err)
	}
	aesPayload, err := base64.StdEncoding.DecodeString(aesPayloadB64)
	if err != nil {
		panic(err)
	}
	// fmt.Printf("rsaPayload: %x\n", rsaPayload)
	// fmt.Printf("aesPayload: %x\n", aesPayload)

	// decrypt RSA part (1)
	label := []byte("My Payload...")
	rng := rand.Reader
	rsaPlaintext, err := rsa.DecryptOAEP(sha256.New(), rng, key, rsaPayload, label)
	if err != nil {
		panic(err)
	}
	// fmt.Printf("rsaPlaintext: %x\n", rsaPlaintext)

	// Extract key and nonce
	aesKey := rsaPlaintext[:32]
	// fmt.Printf("aesKey: %x, len: %d\n", aesKey, len(aesKey))
	aesNonce := rsaPlaintext[32:]
	// fmt.Printf("aesNonce: %x, len: %d\n", aesNonce, len(aesNonce))

	// use from from RSA part (1) to decrypt AES part (2)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, aesNonce, aesPayload, nil)
	if err != nil {
		panic(err.Error())
	}

	// print decrypted payload
	fmt.Println(string(plaintext))
}
