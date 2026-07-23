"""Minimal DigitalOcean REST client (API v2) over httpx.

Home-side only. Uses the full DO_TOKEN. No SDK dependency -- the three calls we
need (create/get/destroy droplet) are simple REST. The httpx client is
injectable so tests can supply an httpx.MockTransport (no real API calls).
"""
import os
import httpx

API = "https://api.digitalocean.com/v2"


class DOError(RuntimeError):
    pass


class DOClient:
    def __init__(self, token: str | None = None, client: httpx.Client | None = None):
        self.token = token or os.environ.get("DO_TOKEN", "")
        if not self.token:
            raise DOError("DO_TOKEN not set")
        self._client = client or httpx.Client(
            base_url=API,
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=30.0,
        )

    def create_droplet(self, name, region, size, image,
                       ssh_key_fingerprints, user_data, tags=None) -> int:
        body = {
            "name": name, "region": region, "size": size, "image": image,
            "ssh_keys": ssh_key_fingerprints, "user_data": user_data,
            "tags": tags or [],
        }
        r = self._client.post("/droplets", json=body)
        if r.status_code not in (200, 201, 202):
            raise DOError(f"create failed: {r.status_code} {r.text}")
        return r.json()["droplet"]["id"]

    def get_droplet(self, droplet_id: int) -> dict:
        r = self._client.get(f"/droplets/{droplet_id}")
        if r.status_code != 200:
            raise DOError(f"get failed: {r.status_code} {r.text}")
        d = r.json()["droplet"]
        ip = None
        for net in (d.get("networks") or {}).get("v4", []):
            if net.get("type") == "public":
                ip = net.get("ip_address")
                break
        return {"status": d.get("status"), "ip": ip}

    def destroy_droplet(self, droplet_id: int) -> None:
        r = self._client.delete(f"/droplets/{droplet_id}")
        if r.status_code not in (204, 404):
            raise DOError(f"destroy failed: {r.status_code} {r.text}")
