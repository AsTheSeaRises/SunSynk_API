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

### Option 2: Command-line flags

```bash
python3 sunsynk_get_generation.py --username "your_email" --password "your_password"
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

## Alternatives

- [sunsynk-api-client](https://github.com/jamesridgway/sunsynk-api-client) - Async Python client with more features
- [SunSynk Official OpenAPI](https://openapi.sunsynk.net) - Official API with HMAC-SHA256 authentication

## License

MIT
