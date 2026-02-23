"""SunSynk API client for retrieving solar plant generation data.

Authenticates against the SunSynk API and retrieves current power
generation data for all registered plants.
"""

import argparse
import os
import sys

import requests


DEFAULT_BASE_URL = "https://api.sunsynk.net"
LOGIN_PATH = "/oauth/token/new"
PLANTS_PATH = "/api/v1/plants?page=1&limit=10&name=&status="


def authenticate(base_url: str, username: str, password: str) -> str:
    """Authenticate with SunSynk and return the access token.

    Args:
        base_url: API base URL.
        username: SunSynk account email.
        password: SunSynk account password.

    Returns:
        Access token string.

    Raises:
        SystemExit: On authentication failure.
    """
    headers = {
        "Content-type": "application/json",
        "Accept": "application/json",
    }
    payload = {
        "username": username,
        "password": password,
        "grant_type": "password",
        "client_id": "csp-web",
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
        sys.exit(1)

    try:
        data = response.json()
        access_token = data["data"]["access_token"]
    except (ValueError, KeyError) as e:
        print(f"Error: Unexpected response format: {e}", file=sys.stderr)
        sys.exit(1)

    return access_token


def get_plant_generation(base_url: str, token: str, verbose: bool = False) -> list[dict]:
    """Retrieve current power generation for all plants.

    Args:
        base_url: API base URL.
        token: Bearer access token.
        verbose: If True, print detailed output.

    Returns:
        List of dicts with 'id' and 'pac' (power in watts) for each plant.

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
