#!/usr/bin/env python3

import argparse
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet
import base64

def load_operator_private_key(key_path):
    """Load operator's private key from file"""
    with open(key_path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def extract_public_key(encrypted_file):
    """Extract public key from encrypted file"""
    with open(encrypted_file, 'rb') as f:
        content = f.read()
        
    # Find the markers
    start_marker = b'\n===BEGIN FILE PUBLIC KEY===\n'
    end_marker = b'\n===END FILE PUBLIC KEY===\n'
    
    start_idx = content.find(start_marker)
    end_idx = content.find(end_marker)
    
    if start_idx == -1 or end_idx == -1:
        raise ValueError("Could not find public key markers in file")
    
    # Extract and parse public key
    public_key_pem = content[start_idx + len(start_marker):end_idx]
    return serialization.load_pem_public_key(public_key_pem)

def get_encrypted_content(encrypted_file):
    """Get only the encrypted content from file (excluding the public key)"""
    with open(encrypted_file, 'rb') as f:
        content = f.read()
    
    start_marker = b'\n===BEGIN FILE PUBLIC KEY===\n'
    start_idx = content.find(start_marker)
    
    if start_idx == -1:
        raise ValueError("Could not find public key marker in file")
    
    return content[:start_idx]

def compute_shared_secret(private_key, peer_public_key):
    """Compute ECDH shared secret and derive encryption key"""
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    
    # Derive encryption key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file-encryption',
    ).derive(shared_secret)
    
    # Convert to Fernet key (32 bytes base64-encoded)
    return base64.urlsafe_b64encode(derived_key)

def decrypt_file(encrypted_file, operator_private_key):
    """Decrypt a file using operator's private key"""
    try:
        # Extract file's public key
        file_public_key = extract_public_key(encrypted_file)
        
        # Compute shared secret
        encryption_key = compute_shared_secret(operator_private_key, file_public_key)
        
        # Get encrypted content
        encrypted_content = get_encrypted_content(encrypted_file)
        
        # Decrypt content
        fernet = Fernet(encryption_key)
        decrypted_content = fernet.decrypt(encrypted_content)
        
        # Save decrypted content
        output_path = Path(str(encrypted_file)[:-4] + '.dec')  # replace .enc with .dec
        output_path.write_bytes(decrypted_content)
        
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
