import pytest
from django.db import IntegrityError, transaction
from opendir.models import Candidate, Snapshot

@pytest.mark.django_db
def test_candidate_defaults():
    c = Candidate.objects.create(dedup_key="ex.com/", url="http://ex.com/", source="fake")
    assert c.status == "pending"
    assert c.source_meta == {}
    assert c.first_seen is not None

@pytest.mark.django_db
def test_dedup_key_unique():
    Candidate.objects.create(dedup_key="ex.com/", url="http://ex.com/", source="fake")
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            Candidate.objects.create(dedup_key="ex.com/", url="http://ex.com/x", source="fake")

@pytest.mark.django_db
def test_snapshot_belongs_to_candidate():
    c = Candidate.objects.create(dedup_key="ex.com/", url="http://ex.com/", source="fake")
    s = Snapshot.objects.create(candidate=c, http_status=200, server_kind="apache",
                                listing_entries=[], entry_count=0, headers=[],
                                raw_html_sha256="a", header_order_sha256="b", template_sha256="c")
    assert s.candidate_id == c.id
    assert c.snapshots.count() == 1
