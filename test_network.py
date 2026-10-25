import socket

PROTECTED_HOST = "10.0.0.4"
PROTECTED_PORT = 8080


def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(3)

    try:
        print(
            f"Testing unauthenticated access to "
            f"{PROTECTED_HOST}:{PROTECTED_PORT}"
        )
        client.connect((PROTECTED_HOST, PROTECTED_PORT))

    except socket.timeout:
        print("[INCONCLUSIVE] Timeout observed. Verify service health and switch flows before claiming enforcement.")
        raise SystemExit(2)

    except ConnectionRefusedError:
        print(
            "[INCONCLUSIVE] Connection refused. "
            "Check whether the service is listening."
        )
        raise SystemExit(2)

    except OSError as exc:
        print(f"[INCONCLUSIVE] Network error: {exc}")
        raise SystemExit(2)

    else:
        print(
            "[FAIL] Connection succeeded before authentication. "
            "The protected-service rule needs investigation."
        )
        raise SystemExit(1)

    finally:
        client.close()


if __name__ == "__main__":
    main()
