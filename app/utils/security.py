"""Security utilities for the application."""

import secrets
from typing import List

from flask import session


class ContentSecurityPolicyGenerator:
    """Generator for Content Security Policy headers."""

    def __init__(self):
        """Initialize the CSP generator with default directives."""
        self.directives = {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "style-src": ["'self'"],
            "img-src": ["'self'", "data:"],
            "font-src": ["'self'"],
            "connect-src": ["'self'"],
            "frame-src": ["'none'"],
            "object-src": ["'none'"],
            "base-uri": ["'self'"],
            "form-action": ["'self'"],
        }

    def add_directive(self, directive: str, sources: List[str]) -> None:
        """Add or update a CSP directive.

        Args:
            directive: The CSP directive to add/update
            sources: List of sources to allow for this directive
        """
        if directive in self.directives:
            self.directives[directive].extend(sources)
        else:
            self.directives[directive] = sources

    def get_header_value(self) -> str:
        """Generate the complete CSP header value.

        Returns:
            str: The CSP header value
        """
        directives = []
        for directive, sources in self.directives.items():
            # Remove duplicates
            unique_sources = list(dict.fromkeys(sources))
            directives.append(f"{directive} {' '.join(unique_sources)}")

        return "; ".join(directives)


def generate_csrf_token() -> str:
    """Generate a CSRF token and store it in the session.

    Returns:
        str: The generated CSRF token
    """
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(16)

    return session["_csrf_token"]


def validate_csrf_token(token: str) -> bool:
    """Validate a CSRF token against the one stored in session.

    Args:
        token: The token to validate

    Returns:
        bool: True if the token is valid, False otherwise
    """
    session_token = session.get("_csrf_token")
    return not (not session_token or session_token != token)
