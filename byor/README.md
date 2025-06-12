A demonstration of file encryption techniques for educational purposes. This project showcases various cryptographic schemes and file processing strategies.

## Features

- Multiple encryption algorithms (RSA-AES, ECDH-ChaCha20)
- Intelligent file encryption strategies
- Concurrent file processing
- Metadata preservation for decryption

## Quick Start

### Build

```bash
make build
```

### Generate Keys

```bash
# Generate ECDH keys (default)
./bin/keygen -type=ecdh

# Generate RSA keys
./bin/keygen -type=rsa
```

### Encrypt Files

```bash
# Basic encryption
./bin/enc -path=/target/directory

# With options
./bin/enc -path=/target/directory \
  -cipher=ecdh-chacha20 \
  -key=public.key \
  -mode=intelligent \
  -workers=8
```

### Decrypt Files

```bash
# Basic decryption
./bin/dec -path=/target/directory

# With specific keys
./bin/dec -path=/target/directory \
  -ecdh-key=private.key \
  -rsa-key=private.pem \
  -workers=8
```

## Command Line Tools

### keygen

Generates cryptographic key pairs.

```bash
./bin/keygen -type=<ecdh|rsa>
```

Options:

- `-type`: Key type to generate (`ecdh` or `rsa`, default: `ecdh`)

### enc

Encrypts files in a directory.

```bash
./bin/enc -path=<directory> [options]
```

Options:

- `-path`: Directory to encrypt (required)
- `-cipher`: Cipher to use (`ecdh-chacha20` or `rsa-aes`, default: `ecdh-chacha20`)
- `-key`: Path to public key file
- `-mode`: Encryption mode (`intelligent`, `full`, `header`, `partial`, default: `intelligent`)
- `-partial-percent`: Percentage to encrypt per block in partial mode (default: 10)
- `-partial-blocks`: Number of blocks in partial mode (default: 3)
- `-workers`: Number of concurrent workers (default: CPU count)
- `-discovery`: File discovery strategy (`default`, `intelligent`, `shuffle`)

### dec

Decrypts files in a directory.

```bash
./bin/dec -path=<directory> [options]
```

Options:

- `-path`: Directory to decrypt (required)
- `-ecdh-key`: Path to ECDH private key (default: `private.key`)
- `-rsa-key`: Path to RSA private key (default: `private.pem`)
- `-workers`: Number of concurrent workers (default: CPU count)

## Encryption Modes

- **Intelligent**: Automatically selects the best mode based on file type and size
- **Full**: Encrypts the entire file
- **Header**: Encrypts only the first 1MB of the file
- **Partial**: Encrypts multiple segments distributed across the file

## File Discovery Strategies

- **Default**: Standard directory traversal
- **Intelligent**: Prioritizes important file types
- **Shuffle**: Randomizes file processing order

## Testing

```bash
make test
```

## Cleaning

```bash
make clean
```

## Architecture

See [EXPLANATION.md](EXPLANATION.md) for detailed technical documentation.
