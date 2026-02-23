# SunSynk API

Retrieve plant ID and current power generation data from a SunSynk inverter. Use this data to trigger IoT devices, notifications, adjust inverter settings, etc.

> **Note:** This uses the unofficial SunSynk web portal API (`api.sunsynk.net`). SunSynk now offers an [official OpenAPI](https://openapi.sunsynk.net) which may be more stable for production use.

## Requirements

- Python 3.10+
- A SunSynk account at [sunsynk.net](https://sunsynk.net/)
- A SunSynk inverter with internet connectivity via the WiFi data logger ([remote monitoring](https://www.sunsynk.org/remote-monitoring))

## Setup

```bash
pip install -r requirements.txt
```

Dependencies: `requests`, `cryptography` (for RSA password encryption).

## Usage

### Option 1: Environment variables (recommended)

```bash
export SUNSYNK_USERNAME="your_email@example.com"
export SUNSYNK_PASSWORD="your_password"
python3 sunsynk_get_generation.py
```

Or copy `.env.example` to `.env` and source it:

```bash
cp .env.example .env
# Edit .env with your credentials
source .env
python3 sunsynk_get_generation.py
```

> **Tip:** If your password contains `!` or other shell special characters, use single quotes: `--password 'MyP@ss!'`

### Option 2: Command-line flags

```bash
python3 sunsynk_get_generation.py --username "your_email" --password 'your_password'
```

### Options

```
--username    SunSynk account email (or SUNSYNK_USERNAME env var)
--password    SunSynk account password (or SUNSYNK_PASSWORD env var)
--base-url    API base URL (default: https://api.sunsynk.net)
--verbose     Show access token and plant IDs
```

### Example output

```
Current power generation: 3450W
```

With `--verbose`:

```
Access token: eyJhbGciOi...
----------------------------------------
Plant ID: 12345
Current power generation: 3450W
```

## How it works

The script authenticates using SunSynk's signed + encrypted auth flow:

1. Generates a millisecond **nonce** (timestamp) and computes an MD5 **sign**
2. Fetches an RSA **public key** from `/anonymous/publicKey`
3. **RSA-encrypts** the password (PKCS1v15) with the fetched public key
4. Computes a second sign (seeded with the first 10 chars of the public key)
5. POSTs encrypted credentials to `/oauth/token/new` to receive a bearer token
6. Uses the bearer token to query `/api/v1/plants` for generation data

This mirrors the authentication flow used by the [sunsynk.net](https://sunsynk.net) web portal.

## Security notes

- Credentials are never sent in plaintext — the password is RSA-encrypted before transmission
- Environment variables are the recommended way to pass credentials (avoids shell history exposure)
- The access token is hidden by default; use `--verbose` only for debugging
- Never commit your `.env` file (it's in `.gitignore`)

## Alternatives

- [solarsynkv3](https://github.com/martinville/solarsynkv3) - Home Assistant addon with the same auth flow
- [SunSynk Official OpenAPI](https://openapi.sunsynk.net) - Official API with HMAC-SHA256 authentication

## License

MIT
