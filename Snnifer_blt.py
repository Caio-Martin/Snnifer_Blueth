"""
Bluetooth BLE metadata sniffer

Scans for nearby BLE advertisements and prints metadata to the terminal.

Key fields printed per detection:
- timestamp
- address (MAC on most platforms)
- name/local_name
- RSSI (signal strength)
- TX power (if provided)
- manufacturer data (company IDs and hex payload)
- service UUIDs

Requires: bleak

Windows notes:
- This script uses the system Bluetooth stack via Bleak.
- Run PowerShell as a normal user (no admin needed) with Bluetooth enabled.

Usage examples:
  python Snnifer_blt.py --duration 15
  python Snnifer_blt.py --continuous
  python Snnifer_blt.py --duration 30 --filter-name beacon
  python Snnifer_blt.py --csv ble_log.csv --continuous
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import signal
import sys
from datetime import datetime, timezone
from typing import Iterable, Optional

try:
	from bleak import BleakScanner
	from bleak.backends.scanner import AdvertisementData
except Exception as exc:  # pragma: no cover - import guidance
	print("Bleak is required. Install with: pip install bleak", file=sys.stderr)
	raise


def _now_iso() -> str:
	return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _fmt_manu_data(manu: dict[int, bytes] | None) -> str:
	if not manu:
		return "-"
	parts = []
	for cid, payload in manu.items():
		parts.append(f"{cid:#06x}:{payload.hex()}")
	return ",".join(parts)


def _fmt_services(uuids: Iterable[str] | None) -> str:
	if not uuids:
		return "-"
	return ",".join(sorted(uuids))


class CsvWriter:
	def __init__(self, path: Optional[str]):
		self._path = path
		self._fh = None
		self._writer = None

	def open(self):
		if not self._path:
			return
		self._fh = open(self._path, "a", newline="", encoding="utf-8")
		self._writer = csv.writer(self._fh)
		# Write header if file is empty
		if self._fh.tell() == 0:
			self._writer.writerow(
				[
					"timestamp",
					"address",
					"name",
					"rssi",
					"tx_power",
					"manufacturer_data",
					"service_uuids",
				]
			)

	def write(
		self,
		timestamp: str,
		address: str,
		name: Optional[str],
		rssi: Optional[int],
		tx_power: Optional[int],
		manufacturer_data: dict[int, bytes] | None,
		service_uuids: Iterable[str] | None,
	):
		if not self._writer:
			return
		self._writer.writerow(
			[
				timestamp,
				address,
				name or "",
				rssi if rssi is not None else "",
				tx_power if tx_power is not None else "",
				_fmt_manu_data(manufacturer_data),
				_fmt_services(service_uuids),
			]
		)

	def close(self):
		if self._fh:
			self._fh.close()
			self._fh = None
			self._writer = None


def print_detection(address: str, name: Optional[str], rssi: Optional[int], adv: AdvertisementData):
	ts = _now_iso()
	manu = _fmt_manu_data(adv.manufacturer_data)
	services = _fmt_services(adv.service_uuids)
	txp = adv.tx_power if hasattr(adv, "tx_power") else None

	print(
		f"[{ts}] {address:<20} RSSI={rssi:>4} dBm  TX={txp if txp is not None else '-':>3}  "
		f"Name={name or adv.local_name or '-'}  Manu={manu}  Services={services}"
	)


async def scan_ble(
	duration: Optional[float],
	filter_name: Optional[str],
	filter_address: Optional[str],
	continuous: bool,
	csv_path: Optional[str],
):
	csvw = CsvWriter(csv_path)
	csvw.open()

	stop_event = asyncio.Event()

	def _request_stop(*_args):
		stop_event.set()

	loop = asyncio.get_running_loop()
	for sig in (signal.SIGINT, signal.SIGTERM):
		try:
			loop.add_signal_handler(sig, _request_stop)
		except NotImplementedError:
			# Windows may not support add_signal_handler for SIGTERM
			pass

	last_seen = {}  # address -> last RSSI (for potential future use)

	def on_detect(device, adv: AdvertisementData):
		addr = getattr(device, "address", getattr(device, "mac_address", "?"))
		name = device.name or adv.local_name
		rssi = adv.rssi if getattr(adv, "rssi", None) is not None else getattr(device, "rssi", None)

		if filter_name:
			match = (name or "").lower()
			if filter_name.lower() not in match:
				return

		if filter_address and filter_address.lower() not in addr.lower():
			return

		last_seen[addr] = rssi
		print_detection(addr, name, rssi, adv)
		csvw.write(
			_now_iso(),
			addr,
			name,
			rssi,
			getattr(adv, "tx_power", None),
			adv.manufacturer_data,
			adv.service_uuids,
		)

	scanner = BleakScanner(detection_callback=on_detect)

	try:
		await scanner.start()
		if continuous and duration in (None, 0):
			await stop_event.wait()
		else:
			# Default bounded scan
			try:
				await asyncio.wait_for(
					stop_event.wait(), timeout=None if not duration else duration
				)
			except asyncio.TimeoutError:
				pass
	finally:
		await scanner.stop()
		csvw.close()


def parse_args(argv: list[str]) -> argparse.Namespace:
	p = argparse.ArgumentParser(description="BLE metadata sniffer (Bleak)")
	p.add_argument(
		"--duration",
		type=float,
		default=10.0,
		help="Scan duration in seconds (ignored in --continuous mode). Use 0 for until Ctrl+C.",
	)
	p.add_argument(
		"--continuous",
		action="store_true",
		help="Run until Ctrl+C (overrides --duration).",
	)
	p.add_argument(
		"--filter-name",
		type=str,
		default=None,
		help="Only show devices whose name contains this substring (case-insensitive).",
	)
	p.add_argument(
		"--filter-address",
		type=str,
		default=None,
		help="Only show devices whose address contains this substring (case-insensitive).",
	)
	p.add_argument(
		"--csv",
		type=str,
		default=None,
		help="Optional path to append CSV logs of detections.",
	)
	return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
	args = parse_args(argv or sys.argv[1:])
	duration = None if args.continuous else (None if args.duration == 0 else args.duration)

	try:
		asyncio.run(
			scan_ble(
				duration=duration,
				filter_name=args.filter_name,
				filter_address=args.filter_address,
				continuous=args.continuous,
				csv_path=args.csv,
			)
		)
	except KeyboardInterrupt:
		pass
	return 0


if __name__ == "__main__":
	raise SystemExit(main())

