# PivotMan Test Suite

This directory contains test scripts for PivotMan.

## Running Tests

### Basic Unit Tests
```bash
python3 test/test_basic.py
```

### Manual Testing
For manual testing with actual network scans, use sample commands:

```bash
# Test with localhost (requires nmap installed)
python3 pivotman.py --targets 127.0.0.1 --scan-type sn

# Test with private network range (adjust to your network)
python3 pivotman.py --targets 192.168.1.0/24 --scan-type sn --output json
```

## Test Coverage

- `test_basic.py`: Unit tests for core functionality
  - Target validation (IP addresses and CIDR ranges)
  - PivotMan initialization
  - Output format generation (text and JSON)

## Note on Network Scanning Tests

Full integration tests with nmap require:
1. nmap installed on the system
2. Proper network permissions
3. Valid target hosts

For security and privacy reasons, automated network scanning tests are kept minimal.
