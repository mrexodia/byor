# Technical Explanation

This document provides a detailed technical explanation of the byor project architecture and implementation.

## Overview

The project implements a modular file encryption system with support for multiple cryptographic schemes and intelligent file processing strategies. It's designed to demonstrate various concepts in cryptography, concurrent programming, and system design.

## Architecture

The codebase is organized into several focused packages:

```
pkg/
├── cipher/       # Cryptographic implementations
├── strategy/     # Encryption strategy logic
├── metadata/     # File metadata handling
├── processor/    # Encryption/decryption orchestration
├── discovery/    # File discovery mechanisms
└── worker/       # Concurrent task processing
```

## Core Components

### 1. Cipher Package (`pkg/cipher/`)

Defines the cryptographic interface and implementations:

#### Interface

```go
type Cipher interface {
    Name() string
    NewEncryptionContext() (keyMaterial []byte, stream cipher.Stream, err error)
    LoadDecryptionContext(keyMaterial []byte) (stream cipher.Stream, err error)
}
```

#### Implementations

**RSA-AES (`rsa_aes.go`)**

- Uses RSA-2048 for key exchange
- AES-256 in CTR mode for actual encryption
- Per-file AES key generation
- Key material: RSA-encrypted AES key + IV

**ECDH-ChaCha20 (`ecdh_chacha20.go`)**

- Uses X25519 curve for key agreement
- ChaCha20 stream cipher for encryption
- Ephemeral key pairs per file
- Key material: Ephemeral public key only

### 2. Strategy Package (`pkg/strategy/`)

Implements intelligent encryption modes:

#### Modes

- **Full**: Encrypts entire file
- **Header**: Encrypts first 1MB (effective for many file formats)
- **Partial**: Encrypts distributed segments across the file
- **Intelligent**: Automatically selects mode based on:
  - File extension (databases get full encryption)
  - File size (small files get full encryption)
  - File type (VMs get partial encryption)

#### Segment Calculation

The `CalculateSegments` function determines which parts of a file to encrypt:

- For partial mode, distributes encrypted blocks evenly across the file
- Prevents overlapping segments
- Handles edge cases (files smaller than segment size)

### 3. Metadata Package (`pkg/metadata/`)

Manages encryption metadata storage:

#### Metadata Structure

```go
type Metadata struct {
    CipherType   string
    Mode         Mode
    OriginalSize int64
    KeyMaterial  []byte
    Segments     []Segment
}
```

#### Storage Format

- Metadata is JSON-encoded and appended to the encrypted file
- Footer structure (12 bytes):
  - 8 bytes: Metadata offset
  - 4 bytes: Magic number (0xDEADC0DE)
- Files are renamed with `.ransomx` extension

### 4. Processor Package (`pkg/processor/`)

Orchestrates the encryption/decryption process:

#### Encryption Flow

1. Open file and determine encryption strategy
2. Generate new encryption context (keys)
3. Calculate segments to encrypt
4. Stream-process each segment
5. Append metadata
6. Rename file

#### Decryption Flow

1. Read metadata from file footer
2. Load appropriate cipher
3. Restore encryption context from key material
4. Decrypt each segment
5. Truncate to original size
6. Restore original filename

#### Stream Processing

- Uses 1MB buffer for efficient I/O
- Supports seek-able streams (CTR mode)
- In-place encryption/decryption

### 5. Discovery Package (`pkg/discovery/`)

Implements file discovery strategies:

- **Default**: Standard directory walk
- **Intelligent**: Prioritizes important files
- **Shuffle**: Randomizes processing order

### 6. Worker Package (`pkg/worker/`)

Provides concurrent task processing:

- Worker pool pattern
- Job queue with backpressure
- Error handling and reporting
- Graceful shutdown

## Security Considerations

### Strengths

1. **Per-file keys**: Each file gets unique encryption keys
2. **Strong algorithms**: RSA-2048, AES-256, X25519, ChaCha20
3. **Metadata integrity**: Magic number validation
4. **No key reuse**: Ephemeral keys for ECDH

### Limitations

1. **No authentication**: Uses unauthenticated encryption modes
2. **Metadata in plaintext**: File structure information is visible
3. **Predictable patterns**: Fixed magic numbers and extensions

## Performance Optimizations

1. **Concurrent processing**: Worker pool for parallel file processing
2. **Streaming**: Process files in chunks to handle large files
3. **Selective encryption**: Intelligent mode reduces processing overhead
4. **In-place operations**: Minimize disk I/O

## Use Cases

This design demonstrates several important concepts:

1. **Cryptographic agility**: Support for multiple cipher suites
2. **Strategy pattern**: Flexible encryption modes
3. **Metadata management**: Preserving decryption information
4. **Concurrent systems**: Efficient file processing at scale
5. **Modular design**: Clean separation of concerns

## Educational Value

This project serves as a comprehensive example of:

- Modern Go programming practices
- Cryptographic protocol implementation
- File system operations
- Concurrent programming patterns
- Software architecture principles

## Ethical Considerations

This code is provided for educational purposes to understand:

- How encryption systems work
- Security vulnerabilities to defend against
- Importance of data protection
- Cryptographic best practices

**Never use this code for malicious purposes.**
