import pytest
import re
import sys
import os
import string

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from utils.utils import generate_random_string, sanitize_name, generate_unique_connection_name


def test_generate_random_string():
    """
    GIVEN generate_random_string function
    WHEN calling it with default and custom lengths
    THEN it returns a string of the expected length with valid characters
    """
    # Test default length
    random_str = generate_random_string()
    assert len(random_str) == 12
    assert all(c in (string.ascii_letters + string.digits) for c in random_str)

    # Test custom length
    custom_length = 20
    random_str_custom = generate_random_string(length=custom_length)
    assert len(random_str_custom) == custom_length
    assert all(c in (string.ascii_letters + string.digits) for c in random_str_custom)


def test_sanitize_name():
    """
    GIVEN sanitize_name function
    WHEN calling it with various inputs
    THEN it returns sanitized names according to Kubernetes naming rules
    """
    # Test conversion to lowercase
    assert sanitize_name("UPPERCASE") == "uppercase"

    # Test replacement of invalid characters
    assert sanitize_name("name@with.special#chars") == "name-with-special-chars"

    # Test handling of leading/trailing hyphens
    assert sanitize_name("-leading-hyphens-") == "leading-hyphens"

    # Test handling of multiple consecutive hyphens
    assert sanitize_name("multiple---hyphens") == "multiple-hyphens"

    # Test handling of empty string
    assert sanitize_name("") == "connection"

    # Test handling of string with only invalid characters
    assert sanitize_name("@#$%^&*()") == "connection"

    # Test handling of string that starts with non-alphanumeric
    assert sanitize_name("@starts-with-special") == "starts-with-special"


def test_generate_unique_connection_name():
    """
    GIVEN generate_unique_connection_name function
    WHEN calling it with various inputs
    THEN it returns valid K8s connection names with proper formatting
    """
    # Test basic functionality
    name = generate_unique_connection_name("test-connection")

    # Check name format matches expected pattern (base-uuid)
    assert re.match(r"^test-connection-[0-9a-f-]+$", name)

    # Test with a very long base name
    long_name = "this-is-a-very-long-connection-name-that-exceeds-kubernetes-limit"
    truncated_name = generate_unique_connection_name(long_name)

    # Check the total length doesn't exceed 53 characters
    assert len(truncated_name) <= 53

    # Test with invalid characters
    special_chars_name = "connection@#$name"
    sanitized_name = generate_unique_connection_name(special_chars_name)

    # Verify sanitization was applied
    assert re.match(r"^connection-name-[0-9a-f-]+$", sanitized_name)

    # Test with empty string - actual implementation returns "connection-uuid"
    empty_name = generate_unique_connection_name("")
    assert re.match(r"^connection-[0-9a-f-]+$", empty_name)
