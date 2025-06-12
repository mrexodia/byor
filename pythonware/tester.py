#!/usr/bin/env python3

import argparse
import hashlib
import subprocess
import sys
import os
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

def run_pipeline(directory):
    """Run the complete encryption/decryption pipeline"""
    print("\nExecuting encryption/decryption pipeline...")
    try:
        # Get the directory of the current script
        script_dir = Path(__file__).parent.absolute()
        
        # Generate operator keys
        print("\nGenerating operator keys...")
        subprocess.run([
            sys.executable,
            script_dir / "generate_operator_keys.py"
        ], check=True)

        # Encrypt files
        print("\nEncrypting files...")
        subprocess.run([
            sys.executable,
            script_dir / "locker.py",
            "operator_public.key",
            directory
        ], check=True)

        # Decrypt files
        print("\nDecrypting files...")
        subprocess.run([
            sys.executable,
            script_dir / "decryptor.py",
            "operator_private.key",
            directory
        ], check=True)

        return True

    except subprocess.CalledProcessError as e:
        print(f"Pipeline failed at step: {e.cmd}")
        print(f"Return code: {e.returncode}")
        if e.output:
            print(f"Output: {e.output}")
        return False
    except Exception as e:
        print(f"Pipeline failed with error: {str(e)}")
        return False

def verify_results(directory):
    """Verify the integrity of all processed files"""
    directory = Path(directory)
    if not directory.is_dir():
        print(f"Error: {directory} is not a directory")
        return 1

    # Get all original files (excluding .enc and .dec files)
    original_files = [f for f in directory.iterdir() 
                     if f.is_file() and not f.name.endswith(('.enc', '.dec'))]
    
    total_files = 0
    passed_tests = 0
    failed_tests = []
    
    print("\nVerifying file integrity...")
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
    
    print("\nTest Summary:")
    print(f"Total files tested: {total_files}")
    print(f"Tests passed: {passed_tests}")
    print(f"Tests failed: {len(failed_tests)}")
    
    if failed_tests:
        print("\nFailed files:")
        for file in failed_tests:
            print(f"- {file}")
        return 1
    
    return 0

def cleanup(directory):
    """Clean up temporary files created during testing"""
    directory = Path(directory)
    print("\nCleaning up temporary files...")
    
    # Remove generated keys
    for key_file in ["operator_private.key", "operator_public.key"]:
        try:
            os.remove(key_file)
            print(f"Removed {key_file}")
        except FileNotFoundError:
            pass

    # Remove .enc files
    for enc_file in directory.glob("*.enc"):
        try:
            os.remove(enc_file)
            print(f"Removed {enc_file}")
        except FileNotFoundError:
            pass

    # Remove .dec files
    for dec_file in directory.glob("*.dec"):
        try:
            os.remove(dec_file)
            print(f"Removed {dec_file}")
        except FileNotFoundError:
            pass

def main():
    parser = argparse.ArgumentParser(description='Test file encryption/decryption integrity')
    parser.add_argument('directory', help='Directory containing files to test')
    parser.add_argument('--keep-files', action='store_true',
                      help='Keep temporary files after testing')
    args = parser.parse_args()
    
    # Run the complete pipeline
    if not run_pipeline(args.directory):
        print("Pipeline execution failed!")
        return 1
    
    # Verify results
    result = verify_results(args.directory)
    
    # Clean up unless --keep-files is specified
    if not args.keep_files:
        cleanup(args.directory)
    
    return result

if __name__ == '__main__':
    exit(main())