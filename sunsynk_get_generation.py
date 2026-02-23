"""SunSynk API client for retrieving solar plant generation data.

Authenticates against the SunSynk API and retrieves current power
generation data for all registered plants.

Auth flow (as of Feb 2026):
  1. Generate a millisecond nonce timestamp
  2. Compute publicKey sign = MD5("nonce={nonce}&source={source}POWER_VIEW")
  3. Fetch RSA public key from /anonymous/publicKey
  4. RSA-encrypt the plaintext password (PKCS1v15) with that key
  5. Compute token sign = MD5("nonce={nonce}&source={source}{pk[:10]}")
  6. POST encrypted credentials + nonce + sign to /oauth/token/new
"""

import argparse
import base64
import hashlib
import os
import sys
import time

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


DEFAULT_BASE_URL = "https://api.sunsynk.net"
PUBLIC_KEY_PATH = "/anonymous/publicKey"
LOGIN_PATH = "/oauth/token/new"
PLANTS_PATH = "/api/v1/plants?page=1&limit=10&name=&status="
SOURCE = "sunsynk"
CLIENT_ID = "csp-web"


def _make_nonce() -> int:
    """Return current time as millisecond integer."""
    return int(time.time() * 1000)


def _make_pk_sign(nonce: int, source: str) -> str:
    """Compute MD5 sign for the public key request.

    Formula: MD5("nonce={nonce}&source={source}POWER_VIEW")
    """
    raw = f"nonce={nonce}&source={source}POWER_VIEW"
    return hashlib.md5(raw.encode()).hexdigest()


def _make_token_sign(nonce: int, source: str, pk_string: str) -> str:
    """Compute MD5 sign for the token login request.

    Formula: MD5("nonce={nonce}&source={source}{first_10_chars_of_public_key}")
    """
    raw = f"nonce={nonce}&source={source}{pk_string[:10]}"
    return hashlib.md5(raw.encode()).hexdigest()


def _fetch_public_key(base_url: str, nonce: int, sign: str) -> tuple[str, bytes]:
    """Fetch the RSA public key from the API.

    Args:
        base_url: API base URL.
        nonce: Millisecond timestamp.
        sign: MD5 signature.

    Returns:
        Tuple of (raw_key_string, PEM-encoded public key bytes).
        The raw string is needed to compute the token sign.

    Raises:
        SystemExit: On request failure.
    """
    url = (
        f"{base_url}{PUBLIC_KEY_PATH}"
        f"?nonce={nonce}&source={SOURCE}&sign={sign}"
    )
    try:
        response = requests.get(url, timeout=30)
    except requests.RequestException as e:
        print(f"Error: Failed to fetch public key: {e}", file=sys.stderr)
        sys.exit(1)

    if response.status_code != 200:
        print(
            f"Error: Public key fetch failed (HTTP {response.status_code})",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        data = response.json()
        raw_key = data["data"]
    except (ValueError, KeyError, TypeError) as e:
        print(f"Error: Unexpected public key response: {e}", file=sys.stderr)
        print(f"Full response: {response.text}", file=sys.stderr)
        sys.exit(1)

    # API returns the bare base64 key without PEM headers — wrap it
    pem = f"-----BEGIN PUBLIC KEY-----\n{raw_key}\n-----END PUBLIC KEY-----"
    return raw_key, pem.encode()


def _encrypt_password(public_key_pem: bytes, plaintext: str) -> str:
    """RSA-encrypt a password with the given public key.

    Args:
        public_key_pem: PEM-encoded RSA public key.
        plaintext: Password to encrypt.

    Returns:
        Base64-encoded ciphertext string.
    """
    public_key = serialization.load_pem_public_key(public_key_pem)
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.PKCS1v15(),
    )
    return base64.b64encode(ciphertext).decode()


def authenticate(base_url: str, username: str, password: str) -> str:
    """Authenticate with SunSynk and return an access token.

    Args:
        base_url: API base URL.
        username: SunSynk account email.
        password: SunSynk account password (plaintext).

    Returns:
        Access token string.

    Raises:
        SystemExit: On authentication failure.
    """
    # Step 1: fetch public key (uses its own nonce + sign)
    pk_nonce = _make_nonce()
    pk_sign = _make_pk_sign(pk_nonce, SOURCE)
    raw_key, public_key_pem = _fetch_public_key(base_url, pk_nonce, pk_sign)
    encrypted_password = _encrypt_password(public_key_pem, password)

    # Step 2: compute login nonce + sign (sign includes first 10 chars of public key)
    login_nonce = _make_nonce()
    login_sign = _make_token_sign(login_nonce, SOURCE, raw_key)

    headers = {
        "Content-type": "application/json",
        "Accept": "application/json",
    }
    payload = {
        "username": username,
        "password": encrypted_password,
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "nonce": login_nonce,
        "sign": login_sign,
        "source": SOURCE,
    }

    url = f"{base_url}{LOGIN_PATH}"
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
    except requests.RequestException as e:
        print(f"Error: Failed to connect to {url}: {e}", file=sys.stderr)
        sys.exit(1)

    if response.status_code != 200:
        print(
            f"Error: Authentication failed (HTTP {response.status_code})",
            file=sys.stderr,
        )
        print(f"Response: {response.text}", file=sys.stderr)
        sys.exit(1)

    try:
        data = response.json()
    except ValueError as e:
        print(f"Error: Could not parse response as JSON: {e}", file=sys.stderr)
        print(f"Raw response: {response.text}", file=sys.stderr)
        sys.exit(1)

    if not data.get("data"):
        msg = data.get("msg") or data.get("message") or "unknown error"
        print(f"Error: Authentication rejected by API: {msg}", file=sys.stderr)
        print(f"Full response: {data}", file=sys.stderr)
        sys.exit(1)

    try:
        access_token = data["data"]["access_token"]
    except KeyError as e:
        print(f"Error: Unexpected response format, missing key {e}", file=sys.stderr)
        print(f"Full response: {data}", file=sys.stderr)
        sys.exit(1)

    return access_token


def get_plant_generation(base_url: str, token: str, verbose: bool = False) -> list[dict]:
    """Retrieve current power generation for all plants.

    Args:
        base_url: API base URL.
        token: Bearer access token.
        verbose: If True, print plant IDs alongside generation.

    Returns:
        List of dicts with 'id' and 'pac' (watts) for each plant.

    Raises:
        SystemExit: On API failure.
    """
    headers = {
        "Content-type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }

    url = f"{base_url}{PLANTS_PATH}"
    try:
        response = requests.get(url, headers=headers, timeout=30)
    except requests.RequestException as e:
        print(f"Error: Failed to connect to {url}: {e}", file=sys.stderr)
        sys.exit(1)

    if response.status_code != 200:
        print(
            f"Error: Failed to retrieve plants (HTTP {response.status_code})",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        data = response.json()
        plants = data["data"]["infos"]
    except (ValueError, KeyError) as e:
        print(f"Error: Unexpected response format: {e}", file=sys.stderr)
        sys.exit(1)

    if not plants:
        print("Warning: No plants found for this account.", file=sys.stderr)
        return []

    results = []
    for plant in plants:
        plant_id = plant["id"]
        pac = plant.get("pac", 0)
        results.append({"id": plant_id, "pac": pac})
        if verbose:
            print(f"Plant ID: {plant_id}")
        print(f"Current power generation: {pac}W")

    return results


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Retrieve current solar power generation from SunSynk.",
    )
    parser.add_argument(
        "--username",
        default=os.environ.get("SUNSYNK_USERNAME"),
        help="SunSynk account email (or set SUNSYNK_USERNAME env var)",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("SUNSYNK_PASSWORD"),
        help="SunSynk account password (or set SUNSYNK_PASSWORD env var)",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("SUNSYNK_BASE_URL", DEFAULT_BASE_URL),
        help=f"API base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show access token and plant IDs",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.username or not args.password:
        print(
            "Error: Username and password required. Provide via --username/--password "
            "flags or SUNSYNK_USERNAME/SUNSYNK_PASSWORD environment variables.",
            file=sys.stderr,
        )
        sys.exit(1)

    token = authenticate(args.base_url, args.username, args.password)

    if args.verbose:
        print(f"Access token: {token}")
        print("-" * 40)

    results = get_plant_generation(args.base_url, token, verbose=args.verbose)

    if not results:
        sys.exit(0)

    total_watts = sum(p["pac"] for p in results)
    if len(results) > 1:
        print(f"Total generation across {len(results)} plants: {total_watts}W")


if __name__ == "__main__":
    main()
