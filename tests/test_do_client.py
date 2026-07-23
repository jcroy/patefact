import httpx
import pytest
from opendir.infra.do_client import DOClient, DOError

API = "https://api.digitalocean.com/v2"


def _client(handler):
    inner = httpx.Client(base_url=API, headers={"Authorization": "Bearer tkn"},
                         transport=httpx.MockTransport(handler))
    return DOClient(token="tkn", client=inner)


def test_create_droplet_returns_id_and_sends_bearer():
    seen = {}
    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        seen["path"] = request.url.path
        return httpx.Response(202, json={"droplet": {"id": 999}})
    do = _client(handler)
    did = do.create_droplet(name="n", region="nyc3", size="s-1vcpu-1gb",
                            image="ubuntu-24-04-x64", ssh_key_fingerprints=["fp"],
                            user_data="#cloud-config", tags=["patefact-worker"])
    assert did == 999
    assert seen["auth"] == "Bearer tkn"
    assert seen["path"] == "/v2/droplets"


def test_get_droplet_extracts_public_ip():
    def handler(request):
        return httpx.Response(200, json={"droplet": {"status": "active", "networks": {"v4": [
            {"type": "private", "ip_address": "10.0.0.2"},
            {"type": "public", "ip_address": "5.6.7.8"},
        ]}}})
    do = _client(handler)
    info = do.get_droplet(999)
    assert info == {"status": "active", "ip": "5.6.7.8"}


def test_destroy_droplet_idempotent_on_404():
    def handler(request):
        return httpx.Response(404, json={"id": "not_found"})
    do = _client(handler)
    do.destroy_droplet(999)   # must not raise


def test_create_droplet_raises_on_error():
    def handler(request):
        return httpx.Response(422, json={"message": "bad"})
    do = _client(handler)
    with pytest.raises(DOError):
        do.create_droplet(name="n", region="nyc3", size="s", image="i",
                          ssh_key_fingerprints=[], user_data="x")
