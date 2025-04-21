import pytest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

# Import your models here
# from desktop_manager.models import User


def test_example():
    """
    GIVEN simple test
    WHEN asserting True
    THEN it passes
    """
    assert True


# Example test for database session
def test_db_import():
    """
    GIVEN database module
    WHEN importing database session
    THEN it imports successfully
    """
    from database.core.session import get_db_session

    assert callable(get_db_session)


# Example of a unit test for a model (uncomment and modify as needed)
# def test_new_user():
#     """
#     GIVEN a User model
#     WHEN a new User is created
#     THEN check the fields are defined correctly
#     """
#     user = User("test@example.com", "securepassword")
#     assert user.email == "test@example.com"
#     assert user.password != "securepassword"  # Should be hashed
