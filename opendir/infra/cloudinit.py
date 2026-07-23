"""Render cloud-init user-data for a disposable capture droplet.

Pure (no I/O), so it is unit-testable. The ONLY secret placed on the droplet is
the droplet:delete-only token, used solely by the self-destruct timer to delete
THIS droplet. The full DO_TOKEN and the home IP are never referenced here -- the
function's only inputs are the delete token and the TTL.
"""

import re

_TEMPLATE = """#cloud-config
users:
  - name: worker
    shell: /bin/bash
    sudo: false
write_files:
  - path: /root/self-destruct.sh
    owner: root:root
    permissions: '0600'
    content: |
      #!/bin/bash
      # Delete THIS droplet via the DO API using the delete-only token.
      ID=$(curl -s http://169.254.169.254/metadata/v1/id)
      curl -s -X DELETE \\
        -H "Authorization: Bearer {delete_token}" \\
        "https://api.digitalocean.com/v2/droplets/$ID"
runcmd:
  - systemd-run --on-active={ttl_minutes}min /bin/bash /root/self-destruct.sh
"""


def render_user_data(delete_token: str, ttl_minutes: int = 45) -> str:
    if not delete_token:
        raise ValueError("delete_token is required")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", delete_token):
        raise ValueError("delete_token must be alphanumeric/underscore/hyphen only")
    if int(ttl_minutes) <= 0:
        raise ValueError("ttl_minutes must be positive")
    return _TEMPLATE.format(delete_token=delete_token, ttl_minutes=int(ttl_minutes))
