import pytest
from django.core.management import call_command
from django.core.management.base import CommandError


def test_do_capture_requires_delete_token(monkeypatch):
    monkeypatch.delenv("DO_DELETE_TOKEN", raising=False)
    monkeypatch.setenv("DO_SSH_KEY_FINGERPRINT", "aa:bb:cc")
    with pytest.raises(CommandError):
        call_command("do_capture", "--smoke")


def test_do_capture_requires_ssh_fingerprint(monkeypatch):
    monkeypatch.setenv("DO_DELETE_TOKEN", "dop_v1_validtoken")
    monkeypatch.delenv("DO_SSH_KEY_FINGERPRINT", raising=False)
    with pytest.raises(CommandError):
        call_command("do_capture", "--smoke")


def test_do_capture_requires_do_token(monkeypatch):
    monkeypatch.delenv("DO_TOKEN", raising=False)
    monkeypatch.setenv("DO_DELETE_TOKEN", "dop_v1_validtoken")
    monkeypatch.setenv("DO_SSH_KEY_FINGERPRINT", "aa:bb:cc")
    with pytest.raises(CommandError):
        call_command("do_capture", "--smoke")
