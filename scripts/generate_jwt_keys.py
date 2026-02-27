#!/usr/bin/env python3
"""
Generate RSA Key Pair for JWT Signing

This script generates an RSA key pair (private and public keys) for JWT token signing.
The keys are saved in PEM format in the keys/ directory.

Usage:
    python scripts/generate_jwt_keys.py
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from pathlib import Path
import os


def generate_rsa_key_pair(key_size: int = 2048) -> tuple:
    """
    Generate RSA key pair.
    
    Args:
        key_size: Size of the RSA key in bits (default: 2048)
    
    Returns:
        Tuple of (private_key, public_key) objects
    """
    print(f"Generating {key_size}-bit RSA key pair...")
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    # Extract public key
    public_key = private_key.public_key()
    
    print("✓ Key pair generated successfully")
    return private_key, public_key


def save_private_key(private_key, output_path: str):
    """
    Save private key to file in PEM format.
    
    Args:
        private_key: RSA private key object
        output_path: Path to save the private key
    """
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    with open(output_path, "wb") as f:
        f.write(pem)
    
    # Set restrictive permissions (owner read/write only)
    os.chmod(output_path, 0o600)
    
    print(f"✓ Private key saved to: {output_path}")


def save_public_key(public_key, output_path: str):
    """
    Save public key to file in PEM format.
    
    Args:
        public_key: RSA public key object
        output_path: Path to save the public key
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open(output_path, "wb") as f:
        f.write(pem)
    
    print(f"✓ Public key saved to: {output_path}")


def main():
    """Generate and save RSA key pair for JWT signing"""
    
    # Create keys directory if it doesn't exist
    keys_dir = Path("keys")
    keys_dir.mkdir(exist_ok=True)
    print(f"✓ Keys directory: {keys_dir.absolute()}")
    
    # Define key paths
    private_key_path = keys_dir / "jwt_private.pem"
    public_key_path = keys_dir / "jwt_public.pem"
    
    # Check if keys already exist
    if private_key_path.exists() or public_key_path.exists():
        response = input("\n⚠️  Keys already exist. Overwrite? (yes/no): ")
        if response.lower() not in ["yes", "y"]:
            print("Aborted. Existing keys preserved.")
            return
    
    # Generate key pair
    private_key, public_key = generate_rsa_key_pair(key_size=2048)
    
    # Save keys
    save_private_key(private_key, str(private_key_path))
    save_public_key(public_key, str(public_key_path))
    
    print("\n" + "="*60)
    print("✓ RSA key pair generated successfully!")
    print("="*60)
    print(f"\nPrivate key: {private_key_path.absolute()}")
    print(f"Public key:  {public_key_path.absolute()}")
    print("\n⚠️  IMPORTANT: Keep the private key secure and never commit it to version control!")
    print("   Add 'keys/' to your .gitignore file.")
    print("\n" + "="*60)


if __name__ == "__main__":
    main()
