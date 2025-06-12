package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync/atomic"

	"byor/pkg/cipher"
	"byor/pkg/discovery"
	"byor/pkg/processor"
	"byor/pkg/worker"
)

func main() {
	path := flag.String("path", "", "Path to decrypt")
	ecdhKeyPath := flag.String("ecdh-key", "private.key", "Path to ECDH private key")
	rsaKeyPath := flag.String("rsa-key", "private.pem", "Path to RSA private key")
	workers := flag.Int("workers", runtime.GOMAXPROCS(0), "Number of concurrent workers")
	flag.Parse()

	if *path == "" {
		log.Fatal("Path is required for decryption")
	}

	ciphers, err := initCiphers(*ecdhKeyPath, *rsaKeyPath)
	if err != nil {
		log.Fatalf("Failed to initialize ciphers for decryption: %v", err)
	}

	processFiles(*path, ciphers, *workers)
}

func initCiphers(ecdhKeyFile, rsaKeyFile string) (map[string]cipher.Cipher, error) {
	ciphers := make(map[string]cipher.Cipher)

	ecdhKeyBytes, err := os.ReadFile(ecdhKeyFile)
	if err == nil {
		c, errInit := cipher.NewEcdhChaCha20WithPrivateKey(ecdhKeyBytes)
		if errInit == nil {
			ciphers[c.Name()] = c
		}
	}

	rsaKeyBytes, err := os.ReadFile(rsaKeyFile)
	if err == nil {
		c, errInit := cipher.NewRsaAesWithPrivateKey(rsaKeyBytes)
		if errInit == nil {
			ciphers[c.Name()] = c
		}
	}

	if len(ciphers) == 0 {
		return nil, fmt.Errorf("could not initialize any ciphers for decryption; check key paths")
	}
	return ciphers, nil
}

func processFiles(rootPath string, ciphers map[string]cipher.Cipher, numWorkers int) {
	var processed, failed int64

	p := worker.New(numWorkers, func(job worker.Job) error {
		err := processor.DecryptFile(string(job), ciphers)
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
		discoverer := discovery.NewDiscoverer(discovery.Default, p)
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
