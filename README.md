# Bluetooth BLE Metadata Sniffer

This script scans for nearby Bluetooth Low Energy (BLE) advertisements and prints useful metadata to the terminal.

What you get per detection:
- Timestamp
- Device address
- Name / Local name
- RSSI (signal strength)
- TX power (if provided by the advertiser)
- Manufacturer data (company ID and payload)
- Service UUIDs

## Requirements
- Python 3.8+
- Bluetooth enabled on your machine
- Windows, macOS, or Linux (Windows PowerShell is fine)

Install Python deps:

```pwsh
python -m pip install -r requirements.txt
```

## Run

Finite scan (default 10s):

```pwsh
python .\Snnifer_blt.py
```

Scan for 30 seconds:

```pwsh
python .\Snnifer_blt.py --duration 30
```

Continuous until Ctrl+C:

```pwsh
python .\Snnifer_blt.py --continuous
```

Filter by name substring and log to CSV:

```pwsh
python .\Snnifer_blt.py --filter-name beacon --csv .\ble_log.csv --continuous
```

CSV columns: `timestamp,address,name,rssi,tx_power,manufacturer_data,service_uuids`

## Notes
- Keep the Bluetooth radio turned on and discoverable if needed.
- On Windows, run in a normal PowerShell window; no admin is required.
- If you don't see devices, try moving closer to BLE devices or increasing duration.
