"""Migration script to add encrypted_password column to connections table.

This migration adds the encrypted_password column to the connections table
to support VNC password storage.
"""

from alembic import op
from sqlalchemy import Column, String


# Revision identifiers
revision = "add_encrypted_password"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    """Add encrypted_password column to connections table."""
    op.add_column("connections", Column("encrypted_password", String(255), nullable=True))


def downgrade():
    """Remove encrypted_password column from connections table."""
    op.drop_column("connections", "encrypted_password")
