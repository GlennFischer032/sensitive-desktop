import re
import secrets
import string
import uuid


def generate_random_string(length=12):
    # Generate a random string of fixed length
    characters = string.ascii_letters + string.digits
    return "".join(secrets.choice(characters) for _ in range(length))


def sanitize_name(name):
    # Convert to lowercase
    name = name.lower()
    # Replace any character that is not a-z, 0-9, or hyphen with a hyphen
    name = re.sub(r"[^a-z0-9-]", "-", name)
    # Remove leading and trailing hyphens
    name = name.strip("-")
    # Replace multiple hyphens with a single hyphen
    name = re.sub(r"-+", "-", name)
    # Ensure length does not exceed 53 characters
    if len(name) > 53:
        name = name[:53]
    return name


def generate_unique_connection_name(base_name, username):
    """Generate a deterministic connection name using username as suffix.

    Args:
        base_name: Base name for the connection
        username: Username to use as suffix

    Returns:
        str: Generated connection name in format base_name-username
    """
    # Ensure the total length does not exceed 53 characters
    max_base_length = 53 - len(username) - 1  # Subtract length of suffix and hyphen
    base_name = base_name[:max_base_length]
    name = f"{base_name}-{username}"
    return name
