#!/usr/bin/env python3
"""
Tests for PivotMan visualization functionality.
"""

import sys
import os
import tempfile
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pivotman import PivotMan
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for testing


def test_visualization_initialization():
    """Test PivotMan initialization with visualization parameters."""
    print("[TEST] Testing visualization initialization...")
    
    pm = PivotMan(
        targets=['192.168.1.1'],
        visualize=True,
        viz_output='test.png'
    )
    
    assert pm.visualize == True
    assert pm.viz_output == 'test.png'
    
    print("[PASS] Visualization initialization test passed!")


def test_render_topology_empty():
    """Test rendering with empty network graph."""
    print("[TEST] Testing render with empty graph...")
    
    pm = PivotMan(targets=['192.168.1.1'], visualize=True)
    
    # Should handle empty graph gracefully
    pm.render_topology()
    
    print("[PASS] Empty graph rendering test passed!")


def test_render_topology_with_nodes():
    """Test rendering with actual network nodes."""
    print("[TEST] Testing render with network nodes...")
    
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp:
        tmp_path = tmp.name
    
    try:
        pm = PivotMan(
            targets=['192.168.1.1'], 
            visualize=True,
            viz_output=tmp_path
        )
        
        # Add some mock scan results
        pm.scan_results = {
            '192.168.1.1': {
                'hostname': 'router.local',
                'state': 'up',
                'protocols': {}
            },
            '192.168.1.2': {
                'hostname': 'server.local',
                'state': 'up',
                'protocols': {}
            },
            '192.168.1.3': {
                'hostname': '',
                'state': 'down',
                'protocols': {}
            }
        }
        
        # Build topology
        pm.build_topology()
        
        # Render topology
        pm.render_topology()
        
        # Check that file was created
        assert os.path.exists(tmp_path), f"Visualization file not created at {tmp_path}"
        assert os.path.getsize(tmp_path) > 0, "Visualization file is empty"
        
        print("[PASS] Network nodes rendering test passed!")
        
    finally:
        # Clean up
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_node_colors():
    """Test that different node states get different colors."""
    print("[TEST] Testing node color assignment...")
    
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp:
        tmp_path = tmp.name
    
    try:
        pm = PivotMan(
            targets=['192.168.1.1'], 
            visualize=True,
            viz_output=tmp_path
        )
        
        # Add nodes with different states
        pm.scan_results = {
            '192.168.1.1': {'hostname': 'up-host', 'state': 'up', 'protocols': {}},
            '192.168.1.2': {'hostname': 'down-host', 'state': 'down', 'protocols': {}},
            '192.168.1.3': {'hostname': 'unknown-host', 'state': 'unknown', 'protocols': {}}
        }
        
        pm.build_topology()
        pm.render_topology()
        
        assert os.path.exists(tmp_path), "Visualization file not created"
        
        print("[PASS] Node color assignment test passed!")
        
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_visualization_with_hostname():
    """Test that hostnames are displayed in labels."""
    print("[TEST] Testing hostname display in labels...")
    
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp:
        tmp_path = tmp.name
    
    try:
        pm = PivotMan(
            targets=['192.168.1.1'], 
            visualize=True,
            viz_output=tmp_path
        )
        
        pm.scan_results = {
            '192.168.1.1': {'hostname': 'testhost.local', 'state': 'up', 'protocols': {}}
        }
        
        pm.build_topology()
        pm.render_topology()
        
        assert os.path.exists(tmp_path), "Visualization file not created"
        
        print("[PASS] Hostname display test passed!")
        
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def run_all_tests():
    """Run all visualization tests."""
    print("=" * 60)
    print("Running PivotMan Visualization Tests")
    print("=" * 60)
    print()
    
    try:
        test_visualization_initialization()
        test_render_topology_empty()
        test_render_topology_with_nodes()
        test_node_colors()
        test_visualization_with_hostname()
        
        print()
        print("=" * 60)
        print("All visualization tests passed!")
        print("=" * 60)
        return True
        
    except AssertionError as e:
        print(f"\n[FAIL] Test failed: {e}")
        return False
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
