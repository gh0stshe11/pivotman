# PivotMan

```
 ____  _            _   __  __             
|  _ \(_)_   _____ | |_|  \/  | __ _ _ __  
| |_) | \ \ / / _ \| __| |\/| |/ _` | '_ \ 
|  __/| |\ V / (_) | |_| |  | | (_| | | | |
|_|   |_| \_/ \___/ \__|_|  |_|\__,_|_| |_|
                                            
    Network Topology & Pivoting Tool
```

**PivotMan** is a CLI-based cybersecurity pentesting tool designed for Kali Linux. It automates network scanning using `nmap` and generates network topology maps to assist in penetration testing and security assessments.

## Features

- ✅ **CLI Input Parsing**: Accept IP addresses or CIDR ranges as targets
- ✅ **Flexible Scanning**: Customize nmap scan types and parameters
- ✅ **Network Mapping**: Build network topology from scan results
- ✅ **Visual Topology Rendering**: Generate graphical network visualizations using Matplotlib
- ✅ **Multiple Output Formats**: Plain text and JSON outputs

## Quick Start

### Installation

1. Clone the repository:
```bash
git clone https://github.com/gh0stshe11/pivotman.git
cd pivotman
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Ensure `nmap` is installed:
```bash
sudo apt-get install nmap
```

### Basic Usage

```bash
# Simple ping scan
python3 pivotman.py --targets 192.168.1.1

# Scan a CIDR range
python3 pivotman.py --targets 192.168.1.0/24

# Service version detection with JSON output
sudo python3 pivotman.py --targets 192.168.1.1 --scan-type sV --output json
```

## Usage Examples

### Scan Multiple Targets
```bash
python3 pivotman.py --targets 192.168.1.1,192.168.1.5,10.0.0.1
```

### Scan Top 100 Ports
```bash
python3 pivotman.py --targets 192.168.1.0/24 --scan-type sS --top-ports 100
```

### Export Results to JSON
```bash
python3 pivotman.py --targets 10.0.0.0/24 --output json > results.json
```

### Generate Network Topology Visualization
```bash
# Display interactive visualization
python3 pivotman.py --targets 192.168.1.0/24 --visualize

# Save visualization to file
python3 pivotman.py --targets 192.168.1.0/24 --visualize --viz-output topology.png
```

## Command Line Options

| Option | Required | Description | Example |
|--------|----------|-------------|---------|
| `--targets` | Yes | Comma-separated IP addresses or CIDR ranges | `192.168.1.1,10.0.0.0/24` |
| `--scan-type` | No | Nmap scan type (default: sn for ping scan) | `sS`, `sT`, `sV`, `sC` |
| `--top-ports` | No | Scan top N most common ports | `100`, `1000` |
| `--output` | No | Output format: text or json (default: text) | `text`, `json` |
| `--visualize` | No | Render network topology visualization | (flag, no value) |
| `--viz-output` | No | Save visualization to file (PNG format) | `topology.png` |

## Project Structure

```
/pivotman
├── README.md                 # This file
├── pivotman.py              # Main CLI application
├── requirements.txt         # Python dependencies
├── logo.txt                 # ASCII art logo
├── test/                    # Test scripts
│   ├── README.md
│   └── test_basic.py
└── docs/                    # Documentation
    ├── DESIGN.md
    └── USAGE.md
```

## Documentation

- **[Usage Guide](docs/USAGE.md)**: Detailed usage instructions and examples
- **[Design Documentation](docs/DESIGN.md)**: Architecture and design decisions
- **[Test README](test/README.md)**: Information about running tests

## Requirements

- Python 3.8+
- nmap (system package)
- python-nmap
- networkx
- matplotlib

## Running Tests

```bash
python3 test/test_basic.py
```

## Security & Legal Notice

⚠️ **IMPORTANT**: Only scan networks and systems you own or have explicit written permission to test. Unauthorized network scanning may be illegal in your jurisdiction.

PivotMan is designed for:
- Authorized penetration testing
- Security assessments
- Network inventory and mapping
- Educational purposes in controlled environments

## Future Enhancements

- 🔄 AI-powered Q&A agent for scan analysis
- 🔄 Automated pivoting opportunity detection
- 🔄 Advanced network relationship inference
- 🔄 Enhanced visualization with Graphviz support
- 🔄 Report generation and export

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is intended for educational and authorized security testing purposes only.

## Author

Created for cybersecurity professionals and penetration testers.
