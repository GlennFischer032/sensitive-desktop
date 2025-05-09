#!/usr/bin/env python3
"""
Generate secure credentials for Guacamole Helm chart deployment.
This script creates necessary secrets for a production deployment without requiring
Kubernetes service account permissions.
"""

import os
import secrets
import yaml
import sys
from cryptography.fernet import Fernet


def generate_fernet_key():
    """Generate a valid Fernet key for encryption."""
    return Fernet.generate_key().decode()


def generate_guac_key():
    """Generate a random key for Guacamole JSON authentication."""
    return secrets.token_hex(16)


def generate_db_password():
    """Generate a secure database password."""
    return secrets.token_urlsafe(16)


def generate_random_key(length=32):
    """Generate a random key of specified length."""
    return secrets.token_urlsafe(length)


def update_values_file(values_file, output_file=None):
    """Update the values file with generated credentials."""
    if output_file is None:
        output_file = values_file

    try:
        with open(values_file, "r") as f:
            values = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: Values file '{values_file}' not found.")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}")
        sys.exit(1)

    # Ensure the common section exists
    if "common" not in values:
        values["common"] = {}

    # Ensure credentials section exists
    if "credentials" not in values["common"]:
        values["common"]["credentials"] = {}

    # Ensure database section exists
    if "database" not in values["common"]:
        values["common"]["database"] = {}

    # Generate encryption key if not already set
    if not values["common"]["credentials"].get("encryptionKey"):
        values["common"]["credentials"]["encryptionKey"] = generate_fernet_key()
        print("✓ Generated Fernet encryption key")

    # Generate Guacamole JSON secret key if not already set
    if not values["common"]["credentials"].get("guacamoleJsonSecretKey"):
        values["common"]["credentials"]["guacamoleJsonSecretKey"] = generate_guac_key()
        print("✓ Generated Guacamole JSON secret key")

    # Generate secret key if not already set
    if not values["common"]["credentials"].get("desktopApiSecretKey"):
        values["common"]["credentials"]["desktopApiSecretKey"] = generate_random_key()
        print("✓ Generated application secret key")

    if not values["common"]["credentials"].get("desktopFrontendSecretKey"):
        values["common"]["credentials"][
            "desktopFrontendSecretKey"
        ] = generate_random_key()
        print("✓ Generated frontend secret key")

    # Generate database password if not already set
    if not values["common"]["database"].get("password"):
        values["common"]["database"]["password"] = generate_db_password()
        print("✓ Generated database password")

    # Write updated values to file
    try:
        with open(output_file, "w") as f:
            yaml.dump(values, f, default_flow_style=False)
        print(f"\nValues successfully written to '{output_file}'")
    except Exception as e:
        print(f"Error writing to file: {e}")
        sys.exit(1)


def main():
    """Main function."""
    print("Generating secure credentials for Guacamole deployment...")

    # Check if custom input and output files are specified
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else input_file
        update_values_file(input_file, output_file)
    else:
        # Default: Try values.local.yaml, then values.yaml
        if os.path.exists("values.local.yaml"):
            update_values_file("values.local.yaml")
        elif os.path.exists("values.yaml"):
            update_values_file("values.yaml", "values.local.yaml")
        else:
            print("Error: No values file found. Please provide a values file path.")
            print(
                "Usage: python generate-secrets.py [input_values_file] [output_values_file]"
            )
            sys.exit(1)

    print("\nYou can now deploy using:")
    print("helm install guacamole . -n fischer-ns -f values.local.yaml")


if __name__ == "__main__":
    main()
