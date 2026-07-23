import pytest

def test_django_imports():
    from opendir.apps import OpendirConfig
    assert OpendirConfig.name == "opendir"

@pytest.mark.django_db
def test_database_connects():
    from django.db import connection
    with connection.cursor() as cur:
        cur.execute("SELECT 1")
        assert cur.fetchone() == (1,)
