#!/usr/bin/env python3

import argparse
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import x25519

def generate_key_pair():
    """Generate an X25519 key pair"""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, filename):
    """Save private key as raw bytes"""
    private_bytes = private_key.private_bytes_raw()
    Path(filename).write_bytes(private_bytes)

def save_public_key(public_key, filename):
    """Save public key as raw bytes"""
    public_bytes = public_key.public_bytes_raw()
    Path(filename).write_bytes(public_bytes)

def main():
    parser = argparse.ArgumentParser(description='Generate X25519 key pair for the operator')
    parser.add_argument('--private-key', default='operator_private.key',
                      help='Path to save private key (default: operator_private.key)')
    parser.add_argument('--public-key', default='operator_public.key',
                      help='Path to save public key (default: operator_public.key)')
    args = parser.parse_args()

    print(f"Generating X25519 key pair...")
    private_key, public_key = generate_key_pair()
    
    print(f"Saving private key to {args.private_key}")
    save_private_key(private_key, args.private_key)
    
    print(f"Saving public key to {args.public_key}")
    save_public_key(public_key, args.public_key)
    
    print("Key generation complete!")

if __name__ == '__main__':
    main()