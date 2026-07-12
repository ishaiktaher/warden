"""Generate a Fernet key for local vault encryption."""

from cryptography.fernet import Fernet


def main() -> None:
    key = Fernet.generate_key().decode()
    print(key)
    print("Add this line to .env:")
    print(f"VAULT_ENCRYPTION_KEY={key}")


if __name__ == "__main__":
    main()
