import pytest
from django.contrib import admin
from opendir.models import Candidate, Snapshot

def test_models_registered():
    assert admin.site.is_registered(Candidate)
    assert admin.site.is_registered(Snapshot)

@pytest.mark.django_db
def test_admin_candidate_changelist_loads(client, django_user_model):
    django_user_model.objects.create_superuser("a", "a@x.com", "pw")
    client.login(username="a", password="pw")
    Candidate.objects.create(dedup_key="ex.com/", url="http://ex.com/", source="fake")
    resp = client.get("/admin/opendir/candidate/")
    assert resp.status_code == 200
    assert b"http://ex.com/" in resp.content

@pytest.mark.django_db
def test_admin_snapshot_add_view_forbidden(client, django_user_model):
    django_user_model.objects.create_superuser("a", "a@x.com", "pw")
    client.login(username="a", password="pw")
    resp = client.get("/admin/opendir/snapshot/add/")
    assert resp.status_code == 403
