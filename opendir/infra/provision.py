"""Provision and tear down a disposable capture droplet (home-side)."""
import time
from dataclasses import dataclass

from opendir.infra import cloudinit
from opendir.infra.do_client import DOClient
from opendir.infra import deploy


@dataclass
class DropletConfig:
    name: str
    region: str
    size: str
    image: str
    ssh_key_fingerprints: list
    delete_token: str
    ttl_minutes: int = 45
    tags: tuple = ("patefact-worker",)


@dataclass
class DropletHandle:
    id: int
    ip: str


def provision(cfg, client=None, ssh_waiter=None, poll_interval: float = 10.0,
              poll_timeout: float = 300.0, sleep=time.sleep) -> DropletHandle:
    client = client or DOClient()
    ssh_waiter = ssh_waiter or deploy.wait_for_ssh
    user_data = cloudinit.render_user_data(cfg.delete_token, cfg.ttl_minutes)
    droplet_id = client.create_droplet(
        name=cfg.name, region=cfg.region, size=cfg.size, image=cfg.image,
        ssh_key_fingerprints=cfg.ssh_key_fingerprints, user_data=user_data,
        tags=list(cfg.tags),
    )
    try:
        elapsed = 0.0
        ip = None
        while True:
            info = client.get_droplet(droplet_id)
            if info.get("status") == "active" and info.get("ip"):
                ip = info["ip"]
                break
            elapsed += poll_interval
            if elapsed >= poll_timeout:
                raise TimeoutError(f"droplet {droplet_id} not active after {poll_timeout}s")
            sleep(poll_interval)
        ssh_waiter(ip)
        return DropletHandle(id=droplet_id, ip=ip)
    except Exception:
        try:
            client.destroy_droplet(droplet_id)   # never leak a half-created droplet
        except Exception:
            pass
        raise


def teardown(handle, client=None) -> None:
    client = client or DOClient()
    client.destroy_droplet(handle.id)
