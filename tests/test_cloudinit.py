import pytest
from opendir.infra.cloudinit import render_user_data


def test_user_data_embeds_delete_token_and_ttl():
    ud = render_user_data(delete_token="DELETE_ONLY_XYZ", ttl_minutes=30)
    assert "DELETE_ONLY_XYZ" in ud
    assert "--on-active=30min" in ud
    assert ud.lstrip().startswith("#cloud-config")


def test_user_data_creates_unprivileged_worker_and_rootonly_script():
    ud = render_user_data(delete_token="D", ttl_minutes=45)
    assert "name: worker" in ud
    assert "sudo: false" in ud
    assert "/root/self-destruct.sh" in ud
    assert "'0600'" in ud
    assert "owner: root:root" in ud


def test_user_data_requires_token():
    with pytest.raises(ValueError):
        render_user_data(delete_token="")


def test_user_data_never_contains_a_full_token_placeholder():
    # Safety invariant: the function only receives the delete token, so a
    # full-access token can never appear. Guard against a future edit that
    # interpolates something else.
    ud = render_user_data(delete_token="DELETE_ONLY", ttl_minutes=10)
    assert "FULL_TOKEN" not in ud
    assert ud.count("Bearer ") == 1   # exactly the one delete-token bearer line


def test_user_data_rejects_token_with_metacharacters():
    for bad in ['a"b', 'a`b', 'a$(id)', "a\nb", "a b"]:
        with pytest.raises(ValueError):
            render_user_data(delete_token=bad, ttl_minutes=45)


def test_user_data_rejects_nonpositive_ttl():
    for bad in (0, -5):
        with pytest.raises(ValueError):
            render_user_data(delete_token="dop_v1_validtoken", ttl_minutes=bad)
