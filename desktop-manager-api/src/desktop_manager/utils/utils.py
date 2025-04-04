import re
import secrets
import string
import uuid


def generate_random_string(length=12):
    # Generate a random string of fixed length
    characters = string.ascii_letters + string.digits
    return "".join(secrets.choice(characters) for _ in range(length))


def sanitize_name(name):
    r"""Sanitize a name to conform to Kubernetes naming conventions.

    Ensures the name matches the regex pattern:
    ^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$

    Args:
        name: The input name to sanitize

    Returns:
        A sanitized name that conforms to Kubernetes naming conventions
    """
    # Convert to lowercase
    name = name.lower()
    # Replace any character that is not a-z, 0-9, or hyphen with a hyphen
    name = re.sub(r"[^a-z0-9-]", "-", name)
    # Remove leading and trailing hyphens
    name = name.strip("-")
    # Replace multiple hyphens with a single hyphen
    name = re.sub(r"-+", "-", name)

    # Ensure the name starts with an alphanumeric character
    if name and not re.match(r"^[a-z0-9]", name):
        name = "x" + name

    # If the name is empty after sanitization, provide a default
    if not name:
        name = "connection"

    return name


def generate_unique_connection_name(base_name, username=None):
    r"""Generate a deterministic connection name using a UUID suffix.

    The name will follow the format base_name-uuid where uuid is a short UUID.
    The result will match the regex
    ^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$
    and will not exceed 53 characters.

    Args:
        base_name: Base name for the connection
        username: Ignored, kept for backward compatibility

    Returns:
        str: Generated connection name in format base_name-uuid
    """
    # Generate a short UUID (8 characters)
    suffix = str(uuid.uuid4())

    # Ensure the total length does not exceed 53 characters
    max_base_length = 53 - len(suffix) - 1  # Subtract length of uuid and hyphen

    # Sanitize base_name to ensure it starts and ends with alphanumeric
    base_name = sanitize_name(base_name)

    # Ensure it doesn't start or end with a hyphen to match the regex pattern
    base_name = base_name.strip("-")

    # Truncate if necessary
    if len(base_name) > max_base_length:
        base_name = base_name[:max_base_length]

    # If after all sanitization the base_name is empty, use a default
    if not base_name:
        base_name = "conn"

    # Combine to create the final name
    name = f"{base_name}-{suffix}"

    return name
