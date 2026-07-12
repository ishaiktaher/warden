"""Generate the HMAC key used to sign Warden capability tokens."""

from cryptography.fernet import Fernet


def main() -> None:
    key = Fernet.generate_key().decode()
    print(key)
    print("Add this to .env:")
    print(f"CAPABILITY_SIGNING_KEY={key}")


if __name__ == "__main__":
    main()
