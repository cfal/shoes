#!/usr/bin/env python3
"""Checks the packaged binary, notices, proxy traffic, and graceful shutdown."""

import argparse
import http.client
import http.server
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = b"shoes container smoke test\n"


def docker(*args):
    return subprocess.check_output(["docker", *args], timeout=60)


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def log_message(self, *_args):
        pass


def check_notices(container):
    notice_paths = [
        ROOT / "LICENSE",
        ROOT / "THIRD_PARTY_NOTICES.md",
        *sorted((ROOT / "licenses").glob("*")),
    ]
    for path in notice_paths:
        relative = path.relative_to(ROOT)
        assert docker(
            "exec", container, "cat", f"/usr/share/doc/shoes/{relative}"
        ) == path.read_bytes(), f"Incorrect notice: {relative}"


def check_proxy(container, origin_port):
    address = docker("port", container, "1080/tcp").decode().strip()
    host, port = address.rsplit(":", 1)
    deadline = time.monotonic() + 30
    while True:
        connection = http.client.HTTPConnection(host, int(port), timeout=2)
        try:
            connection.request("GET", f"http://host.docker.internal:{origin_port}/")
            response = connection.getresponse()
            assert response.status == 200, f"Proxy returned {response.status}"
            assert response.read() == PAYLOAD
            return
        except (OSError, http.client.HTTPException):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)
        finally:
            connection.close()


def smoke(image):
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
    assert docker("run", "--rm", image, "--version").strip() == f"shoes {version}".encode()
    tmp_root = Path.home() / "tmp"
    tmp_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="shoes-docker-", dir=tmp_root) as tmp:
        config_dir = Path(tmp)
        config_dir.chmod(0o755)
        config = config_dir / "config.yaml"
        config.write_text('- address: "0.0.0.0:1080"\n  protocol:\n    type: http\n')
        config.chmod(0o644)
        mount = f"{config_dir}:/etc/shoes:ro"
        docker("run", "--rm", "--volume", mount, image, "check", "/etc/shoes/config.yaml")

        with http.server.ThreadingHTTPServer(("0.0.0.0", 0), Origin) as origin:
            origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
            origin_thread.start()
            container = None
            try:
                container = docker(
                    "run", "--detach", "--read-only", "--cap-drop=ALL",
                    "--security-opt=no-new-privileges", "--volume", mount,
                    "--publish", "127.0.0.1::1080",
                    "--add-host", "host.docker.internal:host-gateway", image,
                ).decode().strip()
                assert docker("exec", container, "id", "-u").strip() == b"65532"
                assert b"BEGIN CERTIFICATE" in docker(
                    "exec", container, "cat", "/etc/ssl/certs/ca-certificates.crt"
                )
                check_notices(container)
                check_proxy(container, origin.server_port)

                docker("stop", "--time", "10", container)
                assert docker("inspect", "--format", "{{.State.ExitCode}}", container).strip() == b"0"
            except BaseException:
                if container:
                    subprocess.run(["docker", "logs", container], check=False, timeout=30)
                raise
            finally:
                if container:
                    docker("rm", "--force", container)
                origin.shutdown()
                origin_thread.join(timeout=5)
    print(f"Docker smoke passed: {image}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", help="local image tag or published image digest")
    smoke(parser.parse_args().image)
