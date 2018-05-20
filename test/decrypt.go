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
	"encoding/binary"
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

	key, err := x509.ParsePKCS1PrivateKey(keyPKCS1.Bytes)
	if err != nil {
		panic(err)
	}

	// read payload from stdin
	scanner := bufio.NewScanner(os.Stdin)
	stage := "looking"

	// break out sections
	payloadB64 := ""
	// payloadVersion := ""
	for scanner.Scan() {
		line := scanner.Text()
		switch stage {
		case "looking":
			if strings.HasPrefix(line, "-----BEGIN E2E ENCRYPTED PAYLOAD-----") {
				stage = "started"
			}
		case "started":
			// can catch headers here, until empty line

			if line == "" {
				stage = "rsa"
			}
		case "rsa":
			if !strings.HasPrefix(line, "-----") {
				payloadB64 += strings.Trim(line, "")
			} else if strings.HasPrefix(line, "-----END E2E ENCRYPTED PAYLOAD-----") {
				break
			}
		default:
			panic("invalid state at line: " + line)
		}
	}

	payload, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		panic(err)
	}

	rsaLen := binary.LittleEndian.Uint16(payload[:2])
	rsaPayload := payload[2 : 2+rsaLen]
	aesPayload := payload[2+rsaLen:]

	// decrypt RSA part (1)
	label := []byte("Vault E2E Payload")
	rng := rand.Reader
	rsaPlaintext, err := rsa.DecryptOAEP(sha256.New(), rng, key, rsaPayload, label)
	if err != nil {
		panic(err)
	}

	// Extract key and nonce
	aesKey := rsaPlaintext[:32]
	aesNonce := rsaPlaintext[32:]

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
