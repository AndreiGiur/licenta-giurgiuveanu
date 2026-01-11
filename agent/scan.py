#!/usr/bin/env python3
"""
Exposure Platform Agent - Demo Version
Colectează date simple despre sistem și le trimite la backend.
"""

import platform
import psutil
import socket
import requests
import sys
from datetime import datetime

# Configuration
API_BASE = "http://127.0.0.1:8000/api/v1"
DEVICE_UID = "laptop-work"  # Change this to match your enrolled device
DEVICE_TOKEN = ""  # Paste your device_token here after enrollment


def collect_system_data():
    """Collect basic system information."""
    data = {
        "device_id": DEVICE_UID,
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "hostname": socket.gethostname(),
            "is_admin": False,  # For demo; real check requires platform-specific code
        },
        "network": {
            "open_ports": [],  # Simplified for demo
        },
        "processes": [],
    }

    # Collect running processes (top 10 by memory)
    try:
        processes = []
        for proc in psutil.process_iter(["pid", "name", "memory_info"]):
            try:
                info = proc.info
                processes.append({
                    "pid": info["pid"],
                    "name": info["name"],
                    "memory_mb": info["memory_info"].rss / (1024 * 1024) if info["memory_info"] else 0,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by memory and take top 10
        processes.sort(key=lambda x: x["memory_mb"], reverse=True)
        data["processes"] = processes[:10]
    except Exception as e:
        print(f"Warning: Could not collect processes: {e}")

    return data


def send_scan(data):
    """Send scan data to backend."""
    if not DEVICE_TOKEN:
        print("ERROR: DEVICE_TOKEN is not set. Please enroll your device first.")
        sys.exit(1)

    headers = {
        "X-Device-Token": DEVICE_TOKEN,
        "Content-Type": "application/json",
    }

    try:
        response = requests.post(
            f"{API_BASE}/scans",
            json=data,
            headers=headers,
            timeout=10,
        )
        response.raise_for_status()
        result = response.json()
        return result
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to send scan: {e}")
        sys.exit(1)


def main():
    print("Exposure Platform Agent - Demo")
    print("=" * 50)
    print(f"Device UID: {DEVICE_UID}")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print()

    print("Collecting system data...")
    data = collect_system_data()
    print(f"  - OS: {data['os']['system']} {data['os']['release']}")
    print(f"  - Hostname: {data['os']['hostname']}")
    print(f"  - Processes collected: {len(data['processes'])}")
    print()

    print("Sending scan to backend...")
    result = send_scan(data)
    
    print()
    print("✓ Scan submitted successfully!")
    print(f"  - Scan ID: {result['scan_id']}")
    print(f"  - Exposure Score: {result['exposure_score']}/100")
    print(f"  - Findings: {len(result['findings'])}")
    print()

    if result['findings']:
        print("Findings:")
        for f in result['findings']:
            severity_icon = "🔴" if f['severity'] == 'high' else "🟡" if f['severity'] == 'medium' else "🟢"
            print(f"  {severity_icon} [{f['severity'].upper()}] {f['title']}")
            print(f"     {f['recommendation']}")
        print()

    print(f"View full results at: http://localhost:5173/scans/{result['scan_id']}")


if __name__ == "__main__":
    main()
