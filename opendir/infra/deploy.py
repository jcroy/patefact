"""Drive the capture droplet from home over the system ssh/scp/rsync.

Thin subprocess wrappers. The module-level `_run` seam lets tests substitute a
recorder without spawning processes. Uses the operator's ed25519 key
(DO_SSH_KEY_PATH). Untrusted content is only ever handled ON the droplet.
"""
import os
import shlex
import subprocess
import time

_run = subprocess.run

_SSH_OPTS = ["-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10"]


def _key_path() -> str:
    return os.path.expanduser(os.environ.get("DO_SSH_KEY_PATH", "~/.ssh/id_ed25519"))


def _ssh_base(ip: str) -> list:
    return ["ssh", "-i", _key_path(), *_SSH_OPTS, f"root@{ip}"]


def wait_for_ssh(ip: str, timeout: float = 180.0, interval: float = 5.0, sleep=time.sleep) -> None:
    elapsed = 0.0
    while True:
        proc = _run([*_ssh_base(ip), "true"], capture_output=True, text=True)
        if proc.returncode == 0:
            return
        elapsed += interval
        if elapsed >= timeout:
            raise TimeoutError(f"ssh to {ip} not ready after {timeout}s")
        sleep(interval)


def push_repo(ip: str, repo_dir: str, remote_dir: str = "/opt/patefact") -> None:
    _run([*_ssh_base(ip), f"mkdir -p {remote_dir}"], check=True)
    ssh_cmd = " ".join(["ssh", "-i", _key_path(), *_SSH_OPTS])
    _run([
        "rsync", "-az", "--delete", "-e", ssh_cmd,
        "--exclude", ".git", "--exclude", ".venv", "--exclude", ".env",
        "--exclude", "docs", "--exclude", "__pycache__",
        "--exclude", ".do_runs",
        f"{repo_dir}/", f"root@{ip}:{remote_dir}/",
    ], check=True)


def setup_remote(ip: str, remote_dir: str = "/opt/patefact") -> None:
    # Install uv to a shared location so both root and the worker user can run it,
    # then sync the project deps (no dev group -- tests never run on the droplet).
    _run([*_ssh_base(ip),
          "curl -LsSf https://astral.sh/uv/install.sh | sh && "
          "cp /root/.local/bin/uv /usr/local/bin/uv && "
          f"cd {remote_dir} && /usr/local/bin/uv sync --no-dev"], check=True)


def run_worker(ip: str, urls: list, remote_dir: str = "/opt/patefact", contact: str = "",
               concurrency: int = 1, fetch_timeout: float | None = None) -> None:
    listing = "\n".join(urls)
    _run([*_ssh_base(ip), f"cat > {remote_dir}/urls.txt"], input=listing, text=True, check=True)
    _run([*_ssh_base(ip), f"chown -R worker:worker {remote_dir}"], check=True)
    parts = []
    if contact:                                     # keep first so `env OPENDIR_CONTACT=…` is intact
        parts.append(f"OPENDIR_CONTACT={shlex.quote(contact)}")
    parts.append(f"OPENDIR_WORKER_CONCURRENCY={int(concurrency)}")
    if fetch_timeout:
        parts.append(f"OPENDIR_FETCH_TIMEOUT={float(fetch_timeout)}")
    env = f"env {' '.join(parts)} " if parts else ""
    _run([*_ssh_base(ip),
          f"cd {remote_dir} && sudo -u worker {env}/usr/local/bin/uv run "
          f"python -m opendir.infra.worker {remote_dir}/urls.txt > {remote_dir}/results.jsonl"],
         check=True)


def pull_results(ip: str, dest: str, remote_dir: str = "/opt/patefact") -> str:
    _run(["scp", "-i", _key_path(), *_SSH_OPTS,
          f"root@{ip}:{remote_dir}/results.jsonl", dest], check=True)
    return dest
