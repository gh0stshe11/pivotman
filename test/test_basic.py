#!/usr/bin/env python3
"""
Basic tests for PivotMan functionality.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pivotman import PivotMan
import ipaddress


def test_target_validation():
    """Test IP address and CIDR validation."""
    print("[TEST] Testing target validation...")
    
    pm = PivotMan(targets=['192.168.1.1', '10.0.0.0/24', 'invalid'], scan_type='sn')
    validated = pm.validate_targets()
    
    assert len(validated) == 2, f"Expected 2 valid targets, got {len(validated)}"
    assert '192.168.1.1' in validated
    assert '10.0.0.0/24' in validated
    assert 'invalid' not in validated
    
    print("[PASS] Target validation test passed!")


def test_pivotman_initialization():
    """Test PivotMan class initialization."""
    print("[TEST] Testing PivotMan initialization...")
    
    pm = PivotMan(
        targets=['192.168.1.1'],
        scan_type='sn',
        top_ports=100,
        output_format='json'
    )
    
    assert pm.targets == ['192.168.1.1']
    assert pm.scan_type == 'sn'
    assert pm.top_ports == 100
    assert pm.output_format == 'json'
    assert pm.scan_results == {}
    
    print("[PASS] PivotMan initialization test passed!")


def test_json_output_format():
    """Test JSON output generation."""
    print("[TEST] Testing JSON output format...")
    
    pm = PivotMan(targets=['192.168.1.1'], output_format='json')
    pm.scan_results = {
        '192.168.1.1': {
            'hostname': 'test-host',
            'state': 'up',
            'protocols': {}
        }
    }
    
    output = pm._output_json()
    assert '"scan_results"' in output
    assert '"topology"' in output
    assert '192.168.1.1' in output
    
    print("[PASS] JSON output format test passed!")


def test_text_output_format():
    """Test text output generation."""
    print("[TEST] Testing text output format...")
    
    pm = PivotMan(targets=['192.168.1.1'], output_format='text')
    pm.scan_results = {
        '192.168.1.1': {
            'hostname': 'test-host',
            'state': 'up',
            'protocols': {}
        }
    }
    
    output = pm._output_text()
    assert 'PIVOTMAN SCAN RESULTS' in output
    assert '192.168.1.1' in output
    assert 'test-host' in output
    
    print("[PASS] Text output format test passed!")


def run_all_tests():
    """Run all tests."""
    print("=" * 60)
    print("Running PivotMan Unit Tests")
    print("=" * 60)
    print()
    
    try:
        test_pivotman_initialization()
        test_target_validation()
        test_json_output_format()
        test_text_output_format()
        
        print()
        print("=" * 60)
        print("All tests passed!")
        print("=" * 60)
        return True
        
    except AssertionError as e:
        print(f"\n[FAIL] Test failed: {e}")
        return False
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        return False


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
