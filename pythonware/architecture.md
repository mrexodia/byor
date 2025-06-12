# File Encryption Tool Architecture

## Overview
This tool provides a secure file encryption system using X25519 (Curve25519) for key exchange and shared secret computation. The system is designed for research purposes and implements a unique approach where each file gets its own encryption key pair.

## Components

### 1. Operator Key Generation
The system uses a master operator key pair for coordinating encryption/decryption:
- Generates X25519 key pair for the operator
- Stores private and public keys as raw bytes
- Keys used for computing shared secrets with individual file keys

```mermaid
graph TD
    A[generate_operator_keys.py] --> B[Generate X25519 Key Pair]
    B --> C[operator_private.key<br/>(32 bytes)]
    B --> D[operator_public.key<br/>(32 bytes)]
```

### 2. File Encryption Process
For each file being encrypted:
- Generates unique X25519 key pair
- Computes shared secret using file's private key and operator's public key
- Encrypts file content using derived key
- Appends file's public key (32 bytes) to encrypted file
- Optionally uploads or deletes original file

```mermaid
graph TD
    A[locker.py] --> B[Parse Arguments]
    B --> C[Scan Directory]
    C --> D[For each file]
    D --> E[Generate file-specific X25519 key pair]
    E --> F[Compute shared secret]
    F --> G[Derive encryption key<br/>using HKDF]
    G --> H[Encrypt with Fernet]
    H --> I[Append public key<br/>32 bytes]
    I --> J{Upload option enabled?}
    J -->|Yes| K[Upload encrypted file]
    J -->|No| L{Delete option enabled?}
    L -->|Yes| M[Delete original file]
    L -->|No| N[Keep original file]
```

### 3. File Decryption Process
For each encrypted file:
- Extracts the file's public key (last 32 bytes)
- Computes shared secret using operator's private key and file's public key
- Decrypts file content using derived key
- Saves decrypted file with .dec extension

```mermaid
graph TD
    A[decryptor.py] --> B[Parse Arguments]
    B --> C[Scan Directory]
    C --> D[For each .enc file]
    D --> E[Extract file's public key<br/>last 32 bytes]
    E --> F[Compute shared secret]
    F --> G[Derive encryption key<br/>using HKDF]
    G --> H[Decrypt with Fernet]
    H --> I[Save .dec file]
```

### 4. Integrity Testing
Verifies the encryption/decryption process:
- Computes SHA256 hash of original file
- Computes SHA256 hash of decrypted file
- Compares hashes to ensure data integrity

```mermaid
graph TD
    A[tester.py] --> B[Parse Arguments]
    B --> C[Scan Directory]
    C --> D[For each original file]
    D --> E[Compute original SHA256]
    D --> F[Find corresponding .dec file]
    F --> G[Compute decrypted SHA256]
    G --> H{Compare Hashes}
    H -->|Match| I[Test Passed]
    H -->|Different| J[Test Failed]
```

## Security Considerations

1. **Key Management**
   - Each file gets a unique X25519 key pair
   - File private keys are used only for encryption and immediately discarded
   - 32-byte public keys are stored with encrypted files
   - Operator keys are stored as raw bytes for efficiency

2. **Shared Secret Computation**
   - Uses X25519 (Curve25519) for secure key exchange
   - HKDF for deriving encryption keys from shared secrets
   - Different shared secret for each file
   - Operator's private key required for decryption

3. **File Security**
   - Optional secure deletion of original files
   - Encrypted files contain only ciphertext and 32-byte public key
   - No metadata or file information leaked
   - Fernet provides secure symmetric encryption

## Implementation Notes

1. **Command Line Interface**
   - All components use argparse for consistent CLI
   - Clear error handling and usage instructions
   - Optional flags for upload/delete operations

2. **File Format**
   - Encrypted file structure: [encrypted_content][32_byte_public_key]
   - Fixed-size public key (32 bytes) simplifies extraction
   - No markers or separators needed
   - Efficient binary format

3. **Testing**
   - Integrity verification through SHA256
   - Automated testing of encryption/decryption
   - Verification of file content preservation