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

try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
except ImportError:
    print("Error: matplotlib not installed. Run: pip install -r requirements.txt")
    sys.exit(1)


class PivotMan:
    """Main class for PivotMan network scanning and topology mapping."""
    
    # Visualization constants
    COLOR_UP = '#4CAF50'      # Green for hosts that are up
    COLOR_DOWN = '#F44336'    # Red for hosts that are down
    COLOR_UNKNOWN = '#9E9E9E' # Gray for unknown state
    
    # Layout parameters
    LAYOUT_SMALL_THRESHOLD = 10  # Network size threshold for layout algorithm
    LAYOUT_SMALL_K = 2           # Spring constant for small networks
    LAYOUT_SMALL_ITER = 50       # Iterations for small networks
    LAYOUT_LARGE_K = 1           # Spring constant for large networks
    LAYOUT_LARGE_ITER = 30       # Iterations for large networks
    
    def __init__(self, targets, scan_type='sn', top_ports=None, output_format='text', 
                 visualize=False, viz_output=None):
        """
        Initialize PivotMan scanner.
        
        Args:
            targets: List of IP addresses or CIDR ranges
            scan_type: Type of nmap scan (default: 'sn' for ping scan)
            top_ports: Number of top ports to scan
            output_format: Output format ('text' or 'json')
            visualize: Whether to render network topology visualization
            viz_output: File path to save visualization (default: display interactive)
        """
        self.targets = targets
        self.scan_type = scan_type
        self.top_ports = top_ports
        self.output_format = output_format
        self.visualize = visualize
        self.viz_output = viz_output
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
    
    def render_topology(self):
        """
        Render visual topology representation of the network.
        Uses matplotlib to create a network graph visualization.
        """
        if len(self.network_graph.nodes) == 0:
            print("[-] No network topology to visualize.")
            return
        
        print("[*] Rendering network topology visualization...")
        
        # Create figure and axis
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Choose layout algorithm based on graph size
        if len(self.network_graph.nodes) <= self.LAYOUT_SMALL_THRESHOLD:
            pos = nx.spring_layout(self.network_graph, k=self.LAYOUT_SMALL_K, 
                                 iterations=self.LAYOUT_SMALL_ITER)
        else:
            pos = nx.spring_layout(self.network_graph, k=self.LAYOUT_LARGE_K, 
                                 iterations=self.LAYOUT_LARGE_ITER)
        
        # Prepare node colors based on state
        node_colors = []
        for node in self.network_graph.nodes():
            state = self.network_graph.nodes[node].get('state', 'unknown')
            if state == 'up':
                node_colors.append(self.COLOR_UP)
            elif state == 'down':
                node_colors.append(self.COLOR_DOWN)
            else:
                node_colors.append(self.COLOR_UNKNOWN)
        
        # Draw nodes
        nx.draw_networkx_nodes(
            self.network_graph, pos,
            node_color=node_colors,
            node_size=1500,
            alpha=0.9,
            ax=ax
        )
        
        # Draw edges
        nx.draw_networkx_edges(
            self.network_graph, pos,
            width=2,
            alpha=0.5,
            edge_color='#666666',
            ax=ax
        )
        
        # Prepare node labels
        labels = {}
        for node in self.network_graph.nodes():
            hostname = self.network_graph.nodes[node].get('hostname', '')
            if hostname:
                labels[node] = f"{node}\n({hostname})"
            else:
                labels[node] = node
        
        # Draw labels
        nx.draw_networkx_labels(
            self.network_graph, pos,
            labels,
            font_size=9,
            font_weight='bold',
            ax=ax
        )
        
        # Add title and legend
        ax.set_title('Network Topology Map', fontsize=16, fontweight='bold', pad=20)
        
        # Create legend
        up_patch = mpatches.Patch(color=self.COLOR_UP, label='Host Up')
        down_patch = mpatches.Patch(color=self.COLOR_DOWN, label='Host Down')
        unknown_patch = mpatches.Patch(color=self.COLOR_UNKNOWN, label='Unknown')
        ax.legend(handles=[up_patch, down_patch, unknown_patch], loc='upper right')
        
        # Remove axes
        ax.axis('off')
        
        # Adjust layout
        plt.tight_layout()
        
        # Save or display
        if self.viz_output:
            plt.savefig(self.viz_output, dpi=300, bbox_inches='tight')
            print(f"[+] Visualization saved to: {self.viz_output}")
        else:
            print("[+] Displaying interactive visualization...")
            print("    (Close the window to continue)")
            plt.show()
        
        plt.close()
        
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
        
        # Render visualization if requested
        if self.visualize:
            self.render_topology()
        
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
    
    parser.add_argument(
        '--visualize',
        action='store_true',
        help='Render network topology visualization'
    )
    
    parser.add_argument(
        '--viz-output',
        help='Save visualization to file (e.g., topology.png). If not specified, displays interactively.'
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
        output_format=args.output,
        visualize=args.visualize,
        viz_output=args.viz_output
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
