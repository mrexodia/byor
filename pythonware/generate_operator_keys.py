#!/usr/bin/env python3

import argparse
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

def generate_key_pair():
    """Generate an ECDSA key pair using SECP384R1 curve"""
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, filename):
    """Save private key to file in PEM format"""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    Path(filename).write_bytes(pem)

def save_public_key(public_key, filename):
    """Save public key to file in PEM format"""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    Path(filename).write_bytes(pem)

def main():
    parser = argparse.ArgumentParser(description='Generate ECDSA key pair for the operator')
    parser.add_argument('--private-key', default='operator_private.key',
                      help='Path to save private key (default: operator_private.key)')
    parser.add_argument('--public-key', default='operator_public.key',
                      help='Path to save public key (default: operator_public.key)')
    args = parser.parse_args()

    print(f"Generating ECDSA key pair using SECP384R1 curve...")
    private_key, public_key = generate_key_pair()
    
    print(f"Saving private key to {args.private_key}")
    save_private_key(private_key, args.private_key)
    
    print(f"Saving public key to {args.public_key}")
    save_public_key(public_key, args.public_key)
    
    print("Key generation complete!")

if __name__ == '__main__':
    main()