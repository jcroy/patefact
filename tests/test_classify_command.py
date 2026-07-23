from io import StringIO

import pytest
from django.core.management import call_command

from opendir.classify.features import EXTRACTOR_VERSION
from opendir.classify.rules import RULESET_VERSION
from opendir.models import Candidate, Classification, Snapshot


def _entries(*names, dirs=()):
    return [{"name": n, "is_dir": False} for n in names] + [{"name": d, "is_dir": True} for d in dirs]


def _make_snapshot(url, entries, is_open_dir=True):
    c = Candidate.objects.create(dedup_key=url, url=url, source="fake")
    return Snapshot.objects.create(
        candidate=c,
        http_status=200,
        server_kind="apache",
        is_open_dir=is_open_dir,
        listing_entries=entries,
        entry_count=len(entries),
    )


@pytest.mark.django_db
def test_classify_command_sensitive_exposure():
    _make_snapshot("http://sensitive.example/", _entries(".env", "dump.sql"))
    out = StringIO()
    call_command("classify", stdout=out)

    classification = Classification.objects.get()
    assert classification.label == "sensitive_exposure"
    assert classification.extractor_version == EXTRACTOR_VERSION
    assert classification.ruleset_version == RULESET_VERSION
    assert "sensitive_exposure" in out.getvalue()


@pytest.mark.django_db
def test_classify_command_intentional_public():
    _make_snapshot("http://mirror.example/", _entries("a.zip", "b.iso", "c.tar", "d.deb"))
    out = StringIO()
    call_command("classify", stdout=out)

    classification = Classification.objects.get()
    assert classification.label == "intentional_public"
    assert "intentional_public" in out.getvalue()


@pytest.mark.django_db
def test_classify_command_is_idempotent_for_same_ruleset_version():
    _make_snapshot("http://sensitive.example/", _entries(".env", "dump.sql"))
    call_command("classify", stdout=StringIO())
    call_command("classify", stdout=StringIO())

    assert Classification.objects.count() == 1


@pytest.mark.django_db
def test_classify_command_skips_non_open_dir_snapshot():
    _make_snapshot("http://closed.example/", _entries(".env"), is_open_dir=False)
    call_command("classify", stdout=StringIO())

    assert Classification.objects.count() == 0
