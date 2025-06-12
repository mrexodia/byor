#!/usr/bin/env python3

import argparse
import hashlib
from pathlib import Path

def calculate_sha256(file_path):
    """Calculate SHA256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def verify_file_integrity(original_file, decrypted_file):
    """Compare SHA256 hashes of original and decrypted files"""
    original_hash = calculate_sha256(original_file)
    decrypted_hash = calculate_sha256(decrypted_file)
    
    return {
        'match': original_hash == decrypted_hash,
        'original_hash': original_hash,
        'decrypted_hash': decrypted_hash
    }

def main():
    parser = argparse.ArgumentParser(description='Test file encryption/decryption integrity')
    parser.add_argument('directory', help='Directory containing original and decrypted files')
    args = parser.parse_args()
    
    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"Error: {directory} is not a directory")
        return 1
        
    # Get all original files (excluding .enc and .dec files)
    original_files = [f for f in directory.iterdir() 
                     if f.is_file() and not f.name.endswith(('.enc', '.dec'))]
    
    total_files = 0
    passed_tests = 0
    failed_tests = []
    
    for orig_file in original_files:
        dec_file = directory / f"{orig_file.name}.dec"
        if not dec_file.exists():
            print(f"Warning: No decrypted file found for {orig_file.name}, skipping...")
            continue
            
        total_files += 1
        print(f"\nTesting: {orig_file.name}")
        result = verify_file_integrity(orig_file, dec_file)
        
        if result['match']:
            passed_tests += 1
            print("✓ Integrity check passed!")
        else:
            failed_tests.append(orig_file.name)
            print("✗ Integrity check failed!")
            print(f"Original hash: {result['original_hash']}")
            print(f"Decrypted hash: {result['decrypted_hash']}")
    
    print("\nSummary:")
    print(f"Total files tested: {total_files}")
    print(f"Tests passed: {passed_tests}")
    print(f"Tests failed: {len(failed_tests)}")
    
    if failed_tests:
        print("\nFailed files:")
        for file in failed_tests:
            print(f"- {file}")
        return 1
    
    return 0

if __name__ == '__main__':
    exit(main())