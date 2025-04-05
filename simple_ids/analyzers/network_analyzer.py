import asyncio
import time
import ipaddress
import re

class NetworkAnalyzer:
    def __init__(self):
        # Signature database for known attack patterns
        self.signatures = [
            {
                'id': 'SIG-001',
                'name': 'SSH Brute Force Attempt',
                'pattern': {'dport': 22, 'protocol': 'TCP', 'flags': 'SYN', 'min_packets': 5, 'window_seconds': 60},
                'severity': 'high'
            },
            {
                'id': 'SIG-002',
                'name': 'SQL Injection Attempt',
                'pattern_regex': r'(?i)((SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)\s+.*(FROM|INTO|WHERE|TABLE))',
                'severity': 'critical'
            },
            {
                'id': 'SIG-003',
                'name': 'RDP Connection Attempt',
                'pattern': {'dport': 3389, 'protocol': 'TCP'},
                'severity': 'medium'
            },
            {
                'id': 'SIG-004',
                'name': 'SMB Access Attempt',
                'pattern': {'dport': 445, 'protocol': 'TCP'},
                'severity': 'medium'
            },
            {
                'id': 'SIG-005',
                'name': 'Known Malware C2 Communication',
                'ip_ranges': ['185.193.38.0/24', '92.53.90.0/24', '31.184.196.0/24'],
                'severity': 'critical'
            },
            {
                'id': 'SIG-006',
                'name': 'DNS Tunneling Attempt',
                'pattern': {'dport': 53, 'protocol': 'UDP'},
                'payload_length_min': 200,
                'severity': 'high'
            },
            {
                'id': 'SIG-007',
                'name': 'ICMP Flood',
                'pattern': {'protocol': 'ICMP'},
                'threshold': {'count': 50, 'window_seconds': 10},
                'severity': 'high'
            }
        ]
        
        # Tracking for multi-packet signatures
        self.connection_tracking = {}  # {src_ip+dst_ip+dport: {'count': n, 'first_seen': timestamp}}
        self.protocol_counts = {}  # {src_ip+protocol: {'count': n, 'first_seen': timestamp}}
        
    async def analyze(self, network_data):
        """Analyze network traffic using signature-based detection"""
        if not network_data:
            return []
            
        alerts = []
        current_time = time.time()
        
        # Process each packet against signatures
        for packet in network_data:
            src_ip = packet.get('src', '')
            dst_ip = packet.get('dst', '')
            dst_port = packet.get('dport', 0)
            protocol = packet.get('protocol', '')
            flags = packet.get('flags', '')
            payload = packet.get('payload', '')
            payload_length = packet.get('payload_length', 0)
            
            # Check packet against each signature
            for sig in self.signatures:
                # Pattern-based signature check
                if 'pattern' in sig:
                    pattern = sig['pattern']
                    match = True
                    
                    # Check if packet fields match the pattern
                    for key, value in pattern.items():
                        if key not in packet or packet[key] != value:
                            if key != 'min_packets' and key != 'window_seconds':
                                match = False
                                break
                    
                    if match:
                        # For signatures tracking frequency/counts
                        if 'min_packets' in pattern:
                            conn_key = f"{src_ip}:{dst_ip}:{dst_port}"
                            if conn_key not in self.connection_tracking:
                                self.connection_tracking[conn_key] = {'count': 1, 'first_seen': current_time}
                            else:
                                self.connection_tracking[conn_key]['count'] += 1
                                
                            # Check if threshold is met within time window
                            if (self.connection_tracking[conn_key]['count'] >= pattern['min_packets'] and
                                current_time - self.connection_tracking[conn_key]['first_seen'] <= pattern.get('window_seconds', float('inf'))):
                                alerts.append(self._create_alert(sig, src_ip, dst_ip, dst_port, current_time))
                        else:
                            # Simple pattern match without thresholds
                            if not self._is_internal_ip(src_ip) or 'ignore_internal' not in sig or not sig['ignore_internal']:
                                alerts.append(self._create_alert(sig, src_ip, dst_ip, dst_port, current_time))
                
                # Regex-based payload inspection
                if 'pattern_regex' in sig and payload:
                    if re.search(sig['pattern_regex'], payload):
                        alerts.append(self._create_alert(sig, src_ip, dst_ip, dst_port, current_time))
                
                # Payload length check
                if 'payload_length_min' in sig and payload_length >= sig['payload_length_min']:
                    if 'pattern' in sig:
                        pattern = sig['pattern']
                        if all(packet.get(k, None) == v for k, v in pattern.items() if k != 'min_packets' and k != 'window_seconds'):
                            alerts.append(self._create_alert(sig, src_ip, dst_ip, dst_port, current_time))
                
                # IP range check
                if 'ip_ranges' in sig:
                    for ip_range in sig['ip_ranges']:
                        try:
                            network = ipaddress.ip_network(ip_range)
                            if ipaddress.ip_address(src_ip) in network or ipaddress.ip_address(dst_ip) in network:
                                alerts.append(self._create_alert(sig, src_ip, dst_ip, dst_port, current_time))
                                break
                        except ValueError:
                            pass
                
                # Threshold-based signatures (e.g., ICMP flood)
                if 'threshold' in sig and 'pattern' in sig:
                    pattern = sig['pattern']
                    if all(packet.get(k, None) == v for k, v in pattern.items()):
                        proto_key = f"{src_ip}:{protocol}"
                        if proto_key not in self.protocol_counts:
                            self.protocol_counts[proto_key] = {'count': 1, 'first_seen': current_time}
                        else:
                            self.protocol_counts[proto_key]['count'] += 1
                            
                        if (self.protocol_counts[proto_key]['count'] >= sig['threshold']['count'] and
                            current_time - self.protocol_counts[proto_key]['first_seen'] <= sig['threshold']['window_seconds']):
                            alerts.append(self._create_alert(sig, src_ip, dst_ip, dst_port, current_time))
        
        # Clean up old tracking entries
        self._cleanup_old_entries(current_time - 120)  # Remove entries older than 120 seconds
        
        return alerts
    
    def _create_alert(self, signature, src_ip, dst_ip, dst_port, timestamp):
        """Create a standardized alert from a signature match"""
        return {
            'timestamp': timestamp,
            'signature_id': signature['id'],
            'type': signature['name'],
            'severity': signature['severity'],
            'source': 'signature_detection',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'description': f"{signature['name']} detected from {src_ip} to {dst_ip}:{dst_port}"
        }
        
    def _cleanup_old_entries(self, cutoff_time):
        """Remove old entries from tracking dictionaries"""
        # Clean connection tracking
        for conn_key in list(self.connection_tracking.keys()):
            if self.connection_tracking[conn_key]['first_seen'] < cutoff_time:
                del self.connection_tracking[conn_key]
                
        # Clean protocol counts
        for proto_key in list(self.protocol_counts.keys()):
            if self.protocol_counts[proto_key]['first_seen'] < cutoff_time:
                del self.protocol_counts[proto_key]
                
    def _is_internal_ip(self, ip):
        """Check if IP is in private ranges"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False

    def add_signature(self, signature):
        """Add a new signature to the detection system"""
        if 'id' in signature and 'name' in signature and 'severity' in signature:
            self.signatures.append(signature)
            return True
        return False