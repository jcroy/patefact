import pytest
from opendir.infra.provision import provision, teardown, DropletConfig, DropletHandle


def _cfg():
    return DropletConfig(name="t", region="nyc3", size="s-1vcpu-1gb",
                         image="ubuntu-24-04-x64", ssh_key_fingerprints=["fp"],
                         delete_token="del", ttl_minutes=45)


class FakeClient:
    def __init__(self, statuses):
        self.statuses = list(statuses)
        self.created = None
        self.destroyed = []
    def create_droplet(self, **kw):
        self.created = kw
        return 123
    def get_droplet(self, did):
        return self.statuses.pop(0)
    def destroy_droplet(self, did):
        self.destroyed.append(did)


def test_provision_polls_until_active_then_waits_ssh():
    fc = FakeClient([{"status": "new", "ip": None}, {"status": "active", "ip": "5.6.7.8"}])
    waited = []
    h = provision(_cfg(), client=fc, ssh_waiter=lambda ip: waited.append(ip), sleep=lambda s: None)
    assert isinstance(h, DropletHandle) and h.id == 123 and h.ip == "5.6.7.8"
    assert waited == ["5.6.7.8"]
    assert fc.created["user_data"].lstrip().startswith("#cloud-config")
    assert "del" in fc.created["user_data"]


def test_provision_destroys_on_ssh_failure_no_leak():
    fc = FakeClient([{"status": "active", "ip": "5.6.7.8"}])
    def boom(ip):
        raise TimeoutError("no ssh")
    with pytest.raises(TimeoutError):
        provision(_cfg(), client=fc, ssh_waiter=boom, sleep=lambda s: None)
    assert fc.destroyed == [123]


def test_provision_times_out_and_destroys():
    fc = FakeClient([{"status": "new", "ip": None}] * 5)
    with pytest.raises(TimeoutError):
        provision(_cfg(), client=fc, ssh_waiter=lambda ip: None,
                  poll_interval=10, poll_timeout=20, sleep=lambda s: None)
    assert fc.destroyed == [123]


def test_teardown_destroys():
    fc = FakeClient([])
    teardown(DropletHandle(id=77, ip="1.2.3.4"), client=fc)
    assert fc.destroyed == [77]
