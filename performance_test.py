
import csv
import argparse
import json
import statistics
import socket
import sys
import time
from pathlib import Path

from net_protocol import receive_line, decode_json

AUTH_HOST = "10.0.0.3"
AUTH_PORT = 9000
SERVICE_HOST = "10.0.0.4"
SERVICE_PORT = 8080
TRIALS = 20

RESULTS_FILE = Path(__file__).with_name("performance_results.csv")


def is_original_results(path):
    """Protect both the original pathname and existing filesystem aliases."""
    path = Path(path)
    original = Path(__file__).with_name("performance_results.csv")
    if path.resolve() == original.resolve():
        return True
    return path.exists() and original.exists() and path.samefile(original)


def auth_request(request):
    """Send one newline-delimited JSON request."""
    deadline = time.monotonic() + 5
    with socket.create_connection(
        (AUTH_HOST, AUTH_PORT), timeout=5
    ) as conn:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Authentication operation deadline exceeded")
        conn.settimeout(remaining)
        conn.sendall(json.dumps(request).encode("utf-8") + b"\n")

        line = receive_line(conn, 4096, 5, deadline=deadline)
        if line is None:
            raise ConnectionError("Authentication server closed")
        response = decode_json(line)
        if not isinstance(response, dict):
            raise ValueError("Expected a JSON object response")
        return response


def service_request():
    """Connect to the service, request the protected data, and measure RTT."""
    start = time.perf_counter()
    deadline = time.monotonic() + 5

    with socket.create_connection(
        (SERVICE_HOST, SERVICE_PORT), timeout=5
    ) as conn:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Service operation deadline exceeded")
        conn.settimeout(remaining)
        conn.sendall(b"GET_SECRET\n")

        response = receive_line(conn, 4096, 5, deadline=deadline)
        if response is None:
            raise ConnectionError("Protected service closed")
    elapsed_ms = (time.perf_counter() - start) * 1000

    if not response.startswith("ACCESS GRANTED"):
        raise RuntimeError(f"Unexpected service response: {response}")

    return elapsed_ms


def append_result(mode, trial, login_ms, service_ms, total_ms):
    """Append a measured trial to the results CSV."""
    if is_original_results(RESULTS_FILE):
        raise ValueError("Choose a separate output path to preserve historical results")
    new_file = not RESULTS_FILE.exists() or RESULTS_FILE.stat().st_size == 0
    if not new_file:
        with RESULTS_FILE.open(newline="", encoding="utf-8") as existing:
            reader = csv.DictReader(existing)
            if reader.fieldnames != ["mode", "trial", "login_ms", "service_rtt_ms", "login_to_access_ms"]:
                raise ValueError("Existing output has an unexpected CSV header")
            if any(row["mode"] == mode and row["trial"] == str(trial) for row in reader):
                raise ValueError("This mode/trial already exists; choose a fresh output path")

    with RESULTS_FILE.open("a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        if new_file:
            writer.writerow([
                "mode", "trial", "login_ms",
                "service_rtt_ms", "login_to_access_ms"
            ])

        writer.writerow([
            mode,
            trial,
            "" if login_ms is None else f"{login_ms:.3f}",
            f"{service_ms:.3f}",
            "" if total_ms is None else f"{total_ms:.3f}",
        ])


def run_dynamic():
    login_times = []
    service_times = []
    total_times = []

    for trial in range(1, TRIALS + 1):
        start = time.perf_counter()

        login_start = time.perf_counter()
        response = auth_request({
            "action": "LOGIN",
            "username": "alice",
            "password": "123",
        })
        login_ms = (time.perf_counter() - login_start) * 1000

        if not response.get("ok"):
            raise RuntimeError(f"Login failed: {response}")

        session_id = response["session_id"]

        try:
            service_ms = service_request()
            total_ms = (time.perf_counter() - start) * 1000
        finally:
            logout = auth_request({
                "action": "LOGOUT",
                "session_id": session_id,
            })
            if not logout.get("ok"):
                raise RuntimeError("Logout/revocation was not confirmed")

        login_times.append(login_ms)
        service_times.append(service_ms)
        total_times.append(total_ms)

        append_result("dynamic", trial, login_ms, service_ms, total_ms)
        print(
            f"Trial {trial:02d}: "
            f"login/control={login_ms:.3f} ms, "
            f"service RTT={service_ms:.3f} ms, "
            f"login-to-access={total_ms:.3f} ms"
        )

    print("\n--- Dynamic SDN summary (20 trials) ---")
    print(f"Mean login/control time: {statistics.mean(login_times):.3f} ms")
    print(f"Median login/control time: {statistics.median(login_times):.3f} ms")
    print(f"Mean service RTT:        {statistics.mean(service_times):.3f} ms")
    print(f"Median service RTT:        {statistics.median(service_times):.3f} ms")
    print(f"Mean login-to-access:    {statistics.mean(total_times):.3f} ms")
    print(f"Median login-to-access:    {statistics.median(total_times):.3f} ms")


def run_static():
    service_times = []

    for trial in range(1, TRIALS + 1):
        service_ms = service_request()
        service_times.append(service_ms)

        append_result("static", trial, None, service_ms, None)
        print(f"Trial {trial:02d}: service RTT={service_ms:.3f} ms")

    print("\n--- Static-rule baseline summary (20 trials) ---")
    print(f"Mean service RTT: {statistics.mean(service_times):.3f} ms")
    print(f"Median service RTT: {statistics.median(service_times):.3f} ms")


def main():
    global RESULTS_FILE
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["dynamic", "static"])
    parser.add_argument("--output", type=Path, required=True,
                        help="Separate CSV path; the original results are protected")
    args = parser.parse_args()
    if is_original_results(args.output):
        parser.error("Choose a separate output path to preserve historical results")
    RESULTS_FILE = args.output

    try:
        if args.mode == "dynamic":
            run_dynamic()
        else:
            run_static()

    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"\n[ERROR] Performance test did not finish: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
