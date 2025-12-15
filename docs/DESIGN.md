# PivotMan Design Documentation

## Overview
PivotMan is a CLI-based cybersecurity pentesting tool designed for Kali Linux. It automates network scanning and creates visual network topology maps to assist in penetration testing and security assessments.

## Architecture

### Components

1. **CLI Interface** (`pivotman.py`)
   - Argument parsing using `argparse`
   - User input validation
   - Output formatting (text/JSON)

2. **Network Scanner**
   - Backend: `nmap` via `python-nmap` library
   - Supports multiple scan types (SYN, TCP, service detection, etc.)
   - Target validation for IP addresses and CIDR ranges

3. **Topology Mapper**
   - Graph representation using `NetworkX`
   - Stores host relationships and network structure
   - Visual rendering with Matplotlib
   - Supports interactive display and file export (PNG format)

4. **Data Storage**
   - In-memory storage using Python dictionaries
   - Scan results indexed by host IP
   - Future: Persistent storage (SQLite/JSON files)

## Data Flow

```
User Input (CLI)
    ↓
Target Validation
    ↓
Nmap Scanning
    ↓
Results Parsing
    ↓
Topology Building
    ↓
Visualization (Optional)
    ↓
Output Generation (Text/JSON)
```

## Scan Result Structure

```python
{
    'host_ip': {
        'hostname': 'example.com',
        'state': 'up',
        'protocols': {
            'tcp': {
                80: {
                    'state': 'open',
                    'name': 'http',
                    'product': 'Apache',
                    'version': '2.4.41'
                }
            }
        }
    }
}
```

## Network Graph Structure

- **Nodes**: Discovered hosts
- **Node Attributes**: hostname, state, discovered flag
- **Edges**: Network relationships (future enhancement)

## Visualization System

### Rendering Engine
- **Library**: Matplotlib with NetworkX integration
- **Layout Algorithm**: Spring layout (force-directed graph)
- **Output Formats**: Interactive display (GUI) or PNG file

### Visual Elements
- **Nodes**: Circular representations of network hosts
- **Colors**: 
  - Green (#4CAF50): Hosts in 'up' state
  - Red (#F44336): Hosts in 'down' state
  - Gray (#9E9E9E): Hosts with unknown state
- **Labels**: IP address and hostname (if available)
- **Legend**: Color coding reference
- **Edges**: Connections between hosts (currently minimal, future enhancement)

### Design Decisions
- Used Matplotlib over Graphviz for better Python integration and no external binary dependencies
- Spring layout chosen for automatic node positioning that works well with various network sizes
- High DPI (300) for file output ensures quality for reports and presentations
- Interactive mode allows users to explore large networks by zooming and panning

## Future Enhancements

### Version 2.0
- Enhanced topology rendering with relationship inference
- Graphviz integration as alternative rendering engine
- Traceroute integration for path discovery
- Network relationship inference based on routing tables
- Export topology in multiple formats (SVG, PDF)

### Version 3.0
- AI-powered Q&A agent for scan analysis
- Pivoting opportunity detection
- Automated vulnerability correlation
- Report generation

### Version 4.0
- Web-based dashboard
- Real-time scanning updates
- Multi-user collaboration
- Scan history and comparison

## Security Considerations

1. **Permissions**: Network scanning requires elevated privileges
2. **Legal**: Only scan networks you have permission to test
3. **Rate Limiting**: Implement scan throttling to avoid detection/disruption
4. **Data Handling**: Sanitize and secure scan results
5. **Logging**: Maintain audit logs of all scanning activities

## Dependencies

- Python 3.8+
- python-nmap: Nmap integration
- networkx: Graph data structures
- matplotlib: Future visualization support

## Development Guidelines

1. Keep dependencies minimal
2. Follow PEP 8 style guide
3. Add docstrings to all functions/classes
4. Validate all user inputs
5. Handle errors gracefully
6. Log important events
