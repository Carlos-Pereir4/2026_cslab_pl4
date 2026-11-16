import copy
import pytest
import baseline_secure_coding_api as api

@pytest.fixture(autouse=True)
def restore_grades():
    """Restores the GRADES list to its original state after every test."""
    original = copy.deepcopy(api.GRADES)
    yield
    api.GRADES[:] = original

@pytest.fixture
def client():
    """Provides a Flask test client with isolated sessions."""
    with api.app.test_client() as client:
        yield client