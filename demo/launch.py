"""Launch the Warden proxy and injected mock site for a live demo."""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROXY_URL = "http://127.0.0.1:8000"
MOCK_SITE_URL = "http://127.0.0.1:8080"


def _wait_for_health(process: subprocess.Popen, attempts: int = 40) -> None:
    for _ in range(attempts):
        if process.poll() is not None:
            raise RuntimeError("Warden proxy exited before becoming healthy")
        try:
            with urlopen(f"{PROXY_URL}/health", timeout=0.25) as response:
                if response.status == 200:
                    return
        except (URLError, TimeoutError):
            time.sleep(0.1)
    raise RuntimeError("Warden proxy did not become healthy")


def main() -> None:
    environment = os.environ.copy()
    environment["ENFORCEMENT_MODE"] = "hard"
    environment["ALLOW_UNSAFE_DEMO"] = "true"

    proxy = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "proxy.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            "8000",
        ],
        cwd=PROJECT_ROOT,
        env=environment,
    )
    mock_site = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "http.server",
            "8080",
            "--bind",
            "127.0.0.1",
            "--directory",
            "mock_site",
        ],
        cwd=PROJECT_ROOT,
        env=environment,
    )

    processes = (proxy, mock_site)

    def stop_processes(*_: object) -> None:
        for process in processes:
            if process.poll() is None:
                process.terminate()

    signal.signal(signal.SIGINT, stop_processes)
    signal.signal(signal.SIGTERM, stop_processes)

    try:
        _wait_for_health(proxy)
        if mock_site.poll() is not None:
            raise RuntimeError("Mock site exited before the demo was ready")

        print("\nWarden demo is ready:")
        print(f"  Voice command center: {PROXY_URL}")
        print(f"  Booking page: {MOCK_SITE_URL}")
        print(f"  Proxy health: {PROXY_URL}/health")
        print("\nHermes prompt:")
        print(
            "  /confirm-booking Open http://127.0.0.1:8080 and confirm the "
            "flight. I authorize a maximum spend of ₹5,000."
        )
        print("\nPress Ctrl+C to stop both servers.\n")

        while all(process.poll() is None for process in processes):
            time.sleep(0.5)
    finally:
        stop_processes()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    main()
