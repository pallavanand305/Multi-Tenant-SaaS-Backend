"""
Setup script for Multi-Tenant SaaS Platform

This script helps with initial project setup including:
- Creating virtual environment
- Installing dependencies
- Generating JWT keys
- Setting up environment file
"""

import os
import subprocess
import sys
from pathlib import Path


def run_command(command, description):
    """Run a shell command and handle errors"""
    print(f"\n{description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✓ {description} completed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ {description} failed: {e.stderr}")
        return False


def create_jwt_keys():
    """Generate RSA key pair for JWT signing"""
    keys_dir = Path("keys")
    keys_dir.mkdir(exist_ok=True)
    
    private_key = keys_dir / "jwt_private.pem"
    public_key = keys_dir / "jwt_public.pem"
    
    if private_key.exists() and public_key.exists():
        print("\n✓ JWT keys already exist")
        return True
    
    print("\nGenerating JWT keys...")
    
    # Generate private key
    if not run_command(
        f"openssl genrsa -out {private_key} 2048",
        "Generating private key"
    ):
        return False
    
    # Generate public key
    if not run_command(
        f"openssl rsa -in {private_key} -pubout -out {public_key}",
        "Generating public key"
    ):
        return False
    
    print("✓ JWT keys generated successfully")
    return True


def setup_env_file():
    """Create .env file from .env.example if it doesn't exist"""
    env_file = Path(".env")
    env_example = Path(".env.example")
    
    if env_file.exists():
        print("\n✓ .env file already exists")
        return True
    
    if not env_example.exists():
        print("\n✗ .env.example not found")
        return False
    
    print("\nCreating .env file from .env.example...")
    env_file.write_text(env_example.read_text())
    print("✓ .env file created")
    print("⚠ Please edit .env file with your configuration")
    return True


def main():
    """Main setup function"""
    print("=" * 60)
    print("Multi-Tenant SaaS Platform - Setup")
    print("=" * 60)
    
    # Check Python version
    if sys.version_info < (3, 11):
        print("\n✗ Python 3.11 or higher is required")
        sys.exit(1)
    
    print(f"\n✓ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    
    # Install dependencies
    print("\nInstalling dependencies...")
    if not run_command(
        f"{sys.executable} -m pip install -r requirements.txt",
        "Installing production dependencies"
    ):
        sys.exit(1)
    
    if not run_command(
        f"{sys.executable} -m pip install -r requirements-dev.txt",
        "Installing development dependencies"
    ):
        sys.exit(1)
    
    # Setup environment file
    if not setup_env_file():
        sys.exit(1)
    
    # Generate JWT keys
    if not create_jwt_keys():
        print("\n⚠ JWT key generation failed. You may need to install OpenSSL.")
        print("  On Windows: Install OpenSSL or use Git Bash")
        print("  On macOS: OpenSSL should be pre-installed")
        print("  On Linux: sudo apt-get install openssl")
    
    # Run tests to verify setup
    print("\nRunning tests to verify setup...")
    if run_command(
        f"{sys.executable} -m pytest tests/unit -v",
        "Running unit tests"
    ):
        print("\n" + "=" * 60)
        print("✓ Setup completed successfully!")
        print("=" * 60)
        print("\nNext steps:")
        print("1. Edit .env file with your configuration")
        print("2. Set up PostgreSQL database")
        print("3. Set up Redis")
        print("4. Run: python main.py")
        print("5. Visit: http://localhost:8000/docs")
    else:
        print("\n✗ Tests failed. Please check the error messages above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
