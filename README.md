# TCPD - Tester's Comprehensive PC Diagnostics

A portable CLI tool for diagnosing PC hardware, security, and system health on Windows 10/11.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Windows](https://img.shields.io/badge/platform-Windows%2010%2F11-blue.svg)](https://www.microsoft.com/windows)

## Features

### Hardware Diagnostics
- **CPU**: Model, cores, threads, clock speed, utilization, temperature
- **GPU**: NVIDIA/AMD detection, VRAM, temperature, utilization
- **Memory**: Total RAM, speed, type (DDR4/DDR5), slot usage
- **Storage**: Drive health (SMART), capacity, type (SSD/HDD)
- **Battery**: Health, wear level, charge cycles (laptops)
- **Motherboard**: Manufacturer, model, BIOS version
- **Network Adapters**: All NICs with MAC addresses
- **Peripherals**: Connected USB devices

### Security Checks
- **Antivirus**: Windows Defender status, third-party AV detection
- **Firewall**: All profile states (Domain/Private/Public)
- **Windows Update**: Pending updates, last update date
- **Open Ports**: Listening ports and associated processes
- **Running Processes**: Suspicious process detection
- **Startup Programs**: Auto-start entries
- **Services**: Critical service status
- **Users**: Local accounts, admin status
- **BitLocker**: Encryption status
- **Secure Boot**: UEFI security state
- **UAC**: User Account Control settings
- **Password Policy**: Complexity requirements
- **Event Log**: Recent security events

### Network Diagnostics
- **Connectivity**: Internet access, gateway, DNS
- **WiFi**: Signal strength, security type, nearby networks
- **DNS**: Resolution tests, configured servers
- **Speed Test**: Download/upload speed measurement

### Stress Testing
- **CPU Stress**: Multi-core load test with temperature monitoring
- **GPU Stress**: Graphics card load test
- **Memory Stress**: RAM integrity test

### Additional Tools
- **Live Monitor**: Real-time system metrics dashboard
- **Hardware Info**: Detailed hardware specifications

## Installation

### Option 1: Run from Source

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/tcpd-diagnostics.git
cd tcpd-diagnostics

# Install dependencies
pip install -r requirements.txt

# Run
python diagnostics.py
```

### Option 2: Build Portable Executable

```bash
# Build standalone exe
python build/build.py

# Run from dist/
dist/tcpd.exe
```

## Usage

### Interactive Mode (Recommended)
```bash
python diagnostics.py
# or
tcpd.exe
```
Launches an arrow-key navigable menu for all features.

### Command Line

```bash
# Quick scan (hardware + security basics)
python diagnostics.py scan --mode quick

# Full system scan
python diagnostics.py scan --mode full

# Hardware only
python diagnostics.py hardware

# Security only
python diagnostics.py security

# Network diagnostics
python diagnostics.py network

# Export to JSON
python diagnostics.py scan --mode full --output report.json

# Stress tests
python diagnostics.py stress-cpu --duration 60
python diagnostics.py stress-gpu --duration 60
python diagnostics.py stress-memory --percent 70

# Live monitoring
python diagnostics.py monitor

# Hardware info
python diagnostics.py hwinfo

# List all scanners
python diagnostics.py list-scanners
```

### All Commands

| Command | Description |
|---------|-------------|
| `scan` | Run diagnostics scan |
| `quick` | Quick scan shortcut |
| `full` | Full scan shortcut |
| `hardware` | Hardware-only scan |
| `security` | Security-only scan |
| `network` | Network diagnostics |
| `stress-cpu` | CPU stress test |
| `stress-gpu` | GPU stress test |
| `stress-memory` | Memory stress test |
| `monitor` | Live system monitor |
| `hwinfo` | Hardware information |
| `list-scanners` | Show available scanners |
| `install-deps` | Install dependencies |
| `version` | Show version |

## Requirements

- Windows 10/11
- Python 3.11+ (for source)
- Administrator privileges (for full diagnostics)

### Dependencies

```
psutil>=5.9.0
wmi>=1.5.1
pywin32>=306
py-cpuinfo>=9.0.0
pynvml>=11.5.0
GPUtil>=1.4.0
typer[all]>=0.9.0
rich>=13.7.0
questionary>=2.0.0
pyyaml>=6.0
pydantic>=2.0
```

## Output Example

```
TCPD - Tester's Comprehensive PC Diagnostics
============================================

Running full scan with 26 scanners...

[CPU]      Intel(R) Core(TM) i5-14400F     PASS
[Memory]   31.8 GB DDR5 @ 6000 MHz         PASS
[GPU]      NVIDIA GeForce RTX 4070         PASS
[Storage]  Samsung 990 Pro 1TB             PASS
[Antivirus] Windows Defender: Active       PASS
[Firewall]  All profiles enabled           PASS
...

Summary: 26 checks | 24 passed | 2 warnings | 0 critical
```

## Configuration

Edit `config/thresholds.yaml` to customize warning levels:

```yaml
cpu_temp:
  warning: 75
  critical: 85

disk:
  warning: 85
  critical: 95
```

## License

MIT License - see [LICENSE](LICENSE) file.

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request
