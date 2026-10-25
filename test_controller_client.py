from controller_client import (
    ControllerError,
    send_allow,
    send_revoke,
)


def main():
    passed = 0
    total = 2

    try:
        response = send_allow(
            client_ip="10.0.0.1",
            server_ip="10.0.0.4",
            service_port=8080,
            lease_seconds=60,
        )

        if response == "OK":
            passed += 1
            print("[PASS] ALLOW command acknowledged")

    except (OSError, ValueError, ControllerError) as exc:
        print(f"[ERROR] Controller communication failed: {exc}")
    finally:
        try:
            if send_revoke("10.0.0.1", "10.0.0.4", 8080) == "OK":
                passed += 1
                print("[PASS] REVOKE command acknowledged")
        except (OSError, ValueError, ControllerError) as exc:
            print(f"[ERROR] Cleanup failed: {exc}")

    print(f"\nResult: {passed}/{total} tests passed.")

    if passed != total:
        raise SystemExit(1)


if __name__ == "__main__":
    main()