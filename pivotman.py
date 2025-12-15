#!/usr/bin/env python3
"""
PivotMan - Network Topology & Pivoting Tool
A cybersecurity pentesting tool for automated network scanning and topology mapping.
"""

import argparse
import json
import sys
import os
from pathlib import Path
import ipaddress

try:
    import nmap
except ImportError:
    print("Error: python-nmap not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

try:
    import networkx as nx
except ImportError:
    print("Error: networkx not installed. Run: pip install -r requirements.txt")
    sys.exit(1)


class PivotMan:
    """Main class for PivotMan network scanning and topology mapping."""
    
    def __init__(self, targets, scan_type='sn', top_ports=None, output_format='text'):
        """
        Initialize PivotMan scanner.
        
        Args:
            targets: List of IP addresses or CIDR ranges
            scan_type: Type of nmap scan (default: 'sn' for ping scan)
            top_ports: Number of top ports to scan
            output_format: Output format ('text' or 'json')
        """
        self.targets = targets
        self.scan_type = scan_type
        self.top_ports = top_ports
        self.output_format = output_format
        self.scan_results = {}
        self.network_graph = nx.Graph()
        
    def display_logo(self):
        """Display the PivotMan ASCII logo."""
        logo_path = Path(__file__).parent / 'logo.txt'
        if logo_path.exists():
            with open(logo_path, 'r', encoding='utf-8') as f:
                print(f.read())
        else:
            print("PivotMan - Network Topology & Pivoting Tool")
        print()
    
    def validate_targets(self):
        """Validate IP addresses and CIDR ranges."""
        validated_targets = []
        for target in self.targets:
            try:
                # Check if it's a valid network or IP
                if '/' in target:
                    # CIDR notation
                    network = ipaddress.ip_network(target, strict=False)
                    validated_targets.append(target)
                else:
                    # Single IP
                    ip = ipaddress.ip_address(target)
                    validated_targets.append(target)
            except ValueError as e:
                print(f"Warning: Invalid target '{target}': {e}")
                continue
        
        return validated_targets
    
    def scan_network(self):
        """Execute nmap scan on targets."""
        print(f"[*] Initializing scan...")
        print(f"[*] Targets: {', '.join(self.targets)}")
        print(f"[*] Scan type: {self.scan_type}")
        
        nm = nmap.PortScanner()
        
        # Build nmap arguments
        nmap_args = f"-{self.scan_type}"
        if self.top_ports:
            nmap_args += f" --top-ports {self.top_ports}"
        
        print(f"[*] Nmap arguments: {nmap_args}")
        print()
        
        for target in self.targets:
            try:
                print(f"[*] Scanning {target}...")
                nm.scan(hosts=target, arguments=nmap_args)
                
                # Store results
                for host in nm.all_hosts():
                    self.scan_results[host] = {
                        'hostname': nm[host].hostname(),
                        'state': nm[host].state(),
                        'protocols': {}
                    }
                    
                    # Store protocol/port information if available
                    for proto in nm[host].all_protocols():
                        self.scan_results[host]['protocols'][proto] = {}
                        ports = nm[host][proto].keys()
                        for port in ports:
                            port_info = nm[host][proto][port]
                            self.scan_results[host]['protocols'][proto][port] = port_info
                    
                    # Add to network graph
                    self.network_graph.add_node(host, 
                                               hostname=nm[host].hostname(),
                                               state=nm[host].state())
                    
                print(f"[+] Completed scan of {target}")
                
            except Exception as e:
                print(f"[-] Error scanning {target}: {e}")
                continue
        
        print()
        return self.scan_results
    
    def build_topology(self):
        """Build network topology from scan results."""
        print("[*] Building network topology...")
        
        # For initial version, we create a simple star topology
        # Future versions can infer relationships from routing tables, traceroute, etc.
        
        if len(self.scan_results) > 0:
            # Add edges between discovered hosts (simple approach)
            hosts = list(self.scan_results.keys())
            
            # In a real scenario, we'd determine actual network relationships
            # For now, we'll just note all discovered hosts
            for host in hosts:
                # Add node if not already in graph
                if not self.network_graph.has_node(host):
                    hostname = self.scan_results[host].get('hostname', '')
                    state = self.scan_results[host].get('state', 'unknown')
                    self.network_graph.add_node(host, hostname=hostname, state=state)
                # Add node attributes
                self.network_graph.nodes[host]['discovered'] = True
        
        print(f"[+] Topology built: {len(self.network_graph.nodes)} nodes")
        print()
        
    def generate_output(self):
        """Generate output based on format selection."""
        if self.output_format == 'json':
            return self._output_json()
        else:
            return self._output_text()
    
    def _output_text(self):
        """Generate plain text output."""
        output = []
        output.append("=" * 60)
        output.append("PIVOTMAN SCAN RESULTS")
        output.append("=" * 60)
        output.append("")
        
        for host, data in self.scan_results.items():
            output.append(f"Host: {host}")
            output.append(f"  Hostname: {data.get('hostname', 'N/A')}")
            output.append(f"  State: {data.get('state', 'unknown')}")
            
            if data.get('protocols'):
                output.append("  Open Ports:")
                for proto, ports in data['protocols'].items():
                    for port, port_data in ports.items():
                        service = port_data.get('name', 'unknown')
                        state = port_data.get('state', 'unknown')
                        output.append(f"    {port}/{proto} - {service} ({state})")
            else:
                output.append("  No port information available")
            
            output.append("")
        
        output.append("=" * 60)
        output.append(f"NETWORK TOPOLOGY SUMMARY")
        output.append("=" * 60)
        output.append(f"Total hosts discovered: {len(self.scan_results)}")
        output.append(f"Network nodes: {len(self.network_graph.nodes)}")
        output.append("")
        
        return "\n".join(output)
    
    def _output_json(self):
        """Generate JSON output."""
        output = {
            'scan_results': self.scan_results,
            'topology': {
                'nodes': len(self.network_graph.nodes),
                'edges': len(self.network_graph.edges),
                'hosts': list(self.scan_results.keys())
            }
        }
        return json.dumps(output, indent=2)
    
    def run(self):
        """Execute the full PivotMan workflow."""
        self.display_logo()
        
        # Validate targets
        validated = self.validate_targets()
        if not validated:
            print("[-] No valid targets to scan.")
            return None
        
        self.targets = validated
        
        # Scan network
        self.scan_network()
        
        # Build topology
        self.build_topology()
        
        # Generate output
        output = self.generate_output()
        return output


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='PivotMan - Network Topology & Pivoting Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s --targets 192.168.1.1,192.168.1.5
  %(prog)s --targets 10.0.0.0/24 --scan-type sV --top-ports 100
  %(prog)s --targets 192.168.1.0/24 --output json
        '''
    )
    
    parser.add_argument(
        '--targets',
        required=True,
        help='Comma-separated list of IP addresses or CIDR ranges (e.g., 192.168.1.1,10.0.0.0/24)'
    )
    
    parser.add_argument(
        '--scan-type',
        default='sn',
        help='Nmap scan type (default: sn for ping scan). Examples: sS, sT, sV, sC'
    )
    
    parser.add_argument(
        '--top-ports',
        type=int,
        help='Scan top N most common ports'
    )
    
    parser.add_argument(
        '--output',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )
    
    return parser.parse_args()


def main():
    """Main entry point for PivotMan."""
    args = parse_arguments()
    
    # Parse targets
    targets = [t.strip() for t in args.targets.split(',')]
    
    # Create PivotMan instance
    pm = PivotMan(
        targets=targets,
        scan_type=args.scan_type,
        top_ports=args.top_ports,
        output_format=args.output
    )
    
    # Run scan and generate output
    output = pm.run()
    
    if output:
        print(output)
    else:
        print("[-] Scan completed with no results.")
        sys.exit(1)


if __name__ == '__main__':
    main()
