#!/usr/bin/env python3

import argparse
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Constants for file format
NONCE_SIZE = 12  # AES-GCM nonce size
PUBLIC_KEY_SIZE = 32  # X25519 public key size

def load_operator_private_key(key_path):
    """Load operator's private key from raw bytes"""
    key_bytes = Path(key_path).read_bytes()
    return x25519.X25519PrivateKey.from_private_bytes(key_bytes)

def extract_public_key(encrypted_file):
    """Extract public key bytes from encrypted file"""
    with open(encrypted_file, 'rb') as f:
        # Read all content and get last 32 bytes (public key)
        content = f.read()
        public_key_bytes = content[-PUBLIC_KEY_SIZE:]
        
    return x25519.X25519PublicKey.from_public_bytes(public_key_bytes)

def get_encrypted_parts(encrypted_file):
    """Get nonce and encrypted content from file"""
    with open(encrypted_file, 'rb') as f:
        content = f.read()
    
    # Extract parts:
    # - First 12 bytes: nonce
    # - Middle part: encrypted data
    # - Last 32 bytes: public key
    nonce = content[:NONCE_SIZE]
    encrypted_data = content[NONCE_SIZE:-PUBLIC_KEY_SIZE]
    
    return nonce, encrypted_data

def compute_shared_secret(private_key, peer_public_key):
    """Compute X25519 shared secret and derive encryption key"""
    shared_secret = private_key.exchange(peer_public_key)
    
    # Derive encryption key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes for AES-256
        salt=None,
        info=b'file-encryption',
    ).derive(shared_secret)
    
    return derived_key

def decrypt_file(encrypted_file, operator_private_key):
    """Decrypt a file using operator's private key"""
    try:
        # Extract file's public key
        file_public_key = extract_public_key(encrypted_file)
        
        # Compute shared secret
        encryption_key = compute_shared_secret(operator_private_key, file_public_key)
        
        # Get encrypted parts
        nonce, encrypted_data = get_encrypted_parts(encrypted_file)
        
        # Create AES-GCM cipher and decrypt
        aesgcm = AESGCM(encryption_key)
        decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
        
        # Save decrypted content
        output_path = Path(str(encrypted_file)[:-4] + '.dec')  # replace .enc with .dec
        output_path.write_bytes(decrypted_data)
        
        print(f"Successfully decrypted: {encrypted_file}")
        return True
        
    except Exception as e:
        print(f"Error decrypting {encrypted_file}: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='File decryption tool')
    parser.add_argument('operator_private', help='Path to operator private key')
    parser.add_argument('encrypted_directory', 
                      help='Directory containing encrypted files')
    args = parser.parse_args()
    
    # Load operator's private key
    try:
        operator_private_key = load_operator_private_key(args.operator_private)
    except Exception as e:
        print(f"Error loading operator private key: {str(e)}")
        return 1
    
    # Process all encrypted files in directory
    directory = Path(args.encrypted_directory)
    if not directory.is_dir():
        print(f"Error: {directory} is not a directory")
        return 1
    
    files_processed = 0
    files_succeeded = 0
    
    for file_path in directory.iterdir():
        if file_path.is_file() and file_path.name.endswith('.enc'):
            files_processed += 1
            if decrypt_file(file_path, operator_private_key):
                files_succeeded += 1
    
    print(f"\nDecryption complete!")
    print(f"Files processed: {files_processed}")
    print(f"Successfully decrypted: {files_succeeded}")
    print(f"Failed: {files_processed - files_succeeded}")
    
    return 0 if files_processed == files_succeeded else 1

if __name__ == '__main__':
    exit(main())
