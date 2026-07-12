"""Seed the vault with safe demonstration data."""

from vault import store_secret

# This opaque value represents a Dodo on-demand subscription ID whose payment
# method was pre-authorized by Dodo; it is not a raw card or payment credential.
FAKE_SUBSCRIPTION_ID = "sub_0Nj0X3l2ro0ufOAerCMGE"


def main() -> None:
    store_secret("dodo_payment_method", FAKE_SUBSCRIPTION_ID)
    print("Stored fake secret: dodo_payment_method")


if __name__ == "__main__":
    main()
