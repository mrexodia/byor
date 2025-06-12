package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"byor/pkg/cipher"
)

func main() {
	keyType := flag.String("type", "ecdh", "Type of key to generate (ecdh or rsa)")
	flag.Parse()

	switch *keyType {
	case "ecdh":
		generateECDH()
	case "rsa":
		generateRSA()
	default:
		log.Fatalf("Invalid key type: %s. Use 'ecdh' or 'rsa'.", *keyType)
	}
}

func generateECDH() {
	priv, pub, err := cipher.GenerateEcdhKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate ECDH key pair: %v", err)
	}
	if err := os.WriteFile("private.key", priv.Bytes(), 0600); err != nil {
		log.Fatalf("Failed to write private key: %v", err)
	}
	if err := os.WriteFile("public.key", pub.Bytes(), 0644); err != nil {
		log.Fatalf("Failed to write public key: %v", err)
	}
	fmt.Println("Successfully generated private.key and public.key")
}

func generateRSA() {
	priv, err := cipher.GenerateRSAKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	privPem := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}
	privFile, err := os.Create("private.pem")
	if err != nil {
		log.Fatalf("Failed to create rsa private key file: %v", err)
	}
	defer privFile.Close()
	if err := pem.Encode(privFile, privPem); err != nil {
		log.Fatalf("Failed to write rsa private key to file: %v", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		log.Fatalf("Failed to marshal rsa public key: %v", err)
	}
	pubPem := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
	pubFile, err := os.Create("public.pem")
	if err != nil {
		log.Fatalf("Failed to create rsa public key file: %v", err)
	}
	defer pubFile.Close()
	if err := pem.Encode(pubFile, pubPem); err != nil {
		log.Fatalf("Failed to write rsa public key to file: %v", err)
	}
	fmt.Println("Successfully generated private.pem and public.pem")
}
