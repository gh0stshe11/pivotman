# PivotMan Usage Guide

## Installation

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
# On Kali Linux / Debian / Ubuntu
sudo apt-get install nmap

# On other systems, see: https://nmap.org/download.html
```

## Basic Usage

### Simple Ping Scan
```bash
python3 pivotman.py --targets 192.168.1.1
```

### Multiple Targets
```bash
python3 pivotman.py --targets 192.168.1.1,192.168.1.5,10.0.0.1
```

### CIDR Range Scan
```bash
python3 pivotman.py --targets 192.168.1.0/24
```

### With Custom Scan Type
```bash
# SYN scan (requires root)
sudo python3 pivotman.py --targets 192.168.1.1 --scan-type sS

# Service version detection
sudo python3 pivotman.py --targets 192.168.1.1 --scan-type sV

# Default scripts scan
sudo python3 pivotman.py --targets 192.168.1.1 --scan-type sC
```

### Scan Top Ports
```bash
python3 pivotman.py --targets 192.168.1.0/24 --scan-type sS --top-ports 100
```

### JSON Output
```bash
python3 pivotman.py --targets 192.168.1.1 --output json
```

### Network Topology Visualization
```bash
# Display interactive visualization (window will open)
python3 pivotman.py --targets 192.168.1.0/24 --visualize

# Save visualization to a PNG file
python3 pivotman.py --targets 192.168.1.0/24 --visualize --viz-output network_map.png

# Combine with scanning options
sudo python3 pivotman.py --targets 192.168.1.0/24 --scan-type sV --top-ports 100 --visualize --viz-output detailed_scan.png
```

## Command Line Options

| Option | Required | Description | Example |
|--------|----------|-------------|---------|
| `--targets` | Yes | Comma-separated IP addresses or CIDR ranges | `192.168.1.1,10.0.0.0/24` |
| `--scan-type` | No | Nmap scan type (default: sn) | `sS`, `sT`, `sV`, `sC` |
| `--top-ports` | No | Scan top N ports | `100`, `1000` |
| `--output` | No | Output format (default: text) | `text`, `json` |
| `--visualize` | No | Enable network topology visualization | (flag) |
| `--viz-output` | No | Save visualization to file | `topology.png` |

## Nmap Scan Types

- `sn`: Ping scan (no port scan)
- `sS`: SYN scan (requires root)
- `sT`: TCP connect scan
- `sV`: Service version detection
- `sC`: Run default nmap scripts
- `sU`: UDP scan (requires root)

## Examples

### Example 1: Quick Network Discovery
```bash
python3 pivotman.py --targets 192.168.1.0/24 --scan-type sn
```

### Example 2: Detailed Service Scan
```bash
sudo python3 pivotman.py --targets 192.168.1.10 --scan-type sV --top-ports 1000
```

### Example 3: JSON Export for Further Processing
```bash
python3 pivotman.py --targets 10.0.0.0/24 --scan-type sn --output json > scan_results.json
```

### Example 4: Network Topology Visualization
```bash
# Create a visual map of discovered hosts
python3 pivotman.py --targets 192.168.1.0/24 --visualize --viz-output network_topology.png
```

### Example 5: Complete Workflow with Visualization
```bash
# Scan, analyze, and visualize a network
sudo python3 pivotman.py --targets 10.0.0.0/24 --scan-type sV --top-ports 1000 --visualize --viz-output complete_scan.png --output json > scan_data.json
```

## Output Interpretation

### Text Output
```
==============================================================
PIVOTMAN SCAN RESULTS
==============================================================

Host: 192.168.1.1
  Hostname: router.local
  State: up
  Open Ports:
    22/tcp - ssh (open)
    80/tcp - http (open)
    443/tcp - https (open)

==============================================================
NETWORK TOPOLOGY SUMMARY
==============================================================
Total hosts discovered: 1
Network nodes: 1
```

### JSON Output
```json
{
  "scan_results": {
    "192.168.1.1": {
      "hostname": "router.local",
      "state": "up",
      "protocols": {
        "tcp": {
          "22": {"state": "open", "name": "ssh"},
          "80": {"state": "open", "name": "http"}
        }
      }
    }
  },
  "topology": {
    "nodes": 1,
    "edges": 0,
    "hosts": ["192.168.1.1"]
  }
}
```

## Permissions

Many nmap scan types require root/administrator privileges:
```bash
sudo python3 pivotman.py --targets 192.168.1.1 --scan-type sS
```

## Troubleshooting

### "python-nmap not installed" Error
```bash
pip install python-nmap
```

### "nmap: command not found"
```bash
sudo apt-get install nmap
```

### Permission Denied
Use `sudo` for scans that require elevated privileges (SYN scan, UDP scan, etc.)

### No Results
- Check network connectivity
- Verify target IPs are reachable
- Ensure firewall allows scanning
- Try a simpler scan type (e.g., `-sn` instead of `-sS`)

## Best Practices

1. **Legal Compliance**: Only scan networks you own or have explicit permission to test
2. **Start Small**: Test with single IPs before scanning large ranges
3. **Rate Limiting**: Use appropriate timing options to avoid overwhelming networks
4. **Documentation**: Save scan results for comparison and reporting
5. **Security**: Store scan results securely and handle sensitive data appropriately

## Visualization Features

PivotMan can generate visual network topology maps to help you understand network structure at a glance.

### Color Coding
- **Green nodes**: Hosts that are up and responding
- **Red nodes**: Hosts that are down or not responding  
- **Gray nodes**: Hosts with unknown state

### Node Labels
Each node displays:
- IP address
- Hostname (if available and resolved)

### Usage Tips
- Use `--visualize` without `--viz-output` to display an interactive visualization window
- Use `--viz-output` to save the visualization as a PNG file for reports
- Visualization works best with 2-50 hosts; larger networks may appear cluttered
- The spring layout algorithm automatically arranges nodes for optimal visibility
