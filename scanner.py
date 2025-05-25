#!/usr/bin/env python3
"""
Network Scanner Module
Handles nmap scanning operations with comprehensive port detection
"""

import nmap
import logging
import socket
import subprocess
import platform
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class NetworkScanner:
    """Network scanner using python-nmap library"""
    
    def __init__(self):
        """Initialize the network scanner"""
        self.nm = nmap.PortScanner()
        self._check_nmap_availability()
    
    def _check_nmap_availability(self) -> bool:
        """Check if nmap is available on the system"""
        try:
            # Check if nmap command exists
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=10)
            if result.returncode == 0:
                logger.info(f"Nmap version detected: {result.stdout.split()[2]}")
                return True
            else:
                logger.error("Nmap command failed")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error(f"Nmap not found or not accessible: {e}")
            return False
    
    def scan_host(self, ip_address: str, port_range: str = None) -> Dict[str, Any]:
        """
        Perform comprehensive port scan on target host
        
        Args:
            ip_address: Target IP address to scan
            port_range: Port range to scan (default: all ports)
            
        Returns:
            Dictionary containing scan results
        """
        try:
            logger.info(f"Starting scan of {ip_address}")
            
            # Validate IP address
            if not self._validate_ip(ip_address):
                return {
                    'success': False,
                    'error': f'Invalid IP address: {ip_address}',
                    'timestamp': datetime.now().isoformat()
                }
            
            # Set default port range if not specified
            if port_range is None:
                port_range = '1-65535'  # Scan all ports
            
            # Perform scan without ping (as requested)
            # -sS: SYN scan (stealth scan)
            # -Pn: No ping (skip host discovery)
            # -sV: Version detection
            # -O: OS detection
            # --open: Only show open ports
            scan_args = '-sS -Pn -sV -O --open'
            
            logger.info(f"Scanning {ip_address} with arguments: {scan_args}")
            
            # Perform the scan
            scan_result = self.nm.scan(
                hosts=ip_address,
                ports=port_range,
                arguments=scan_args
            )
            
            # Process scan results
            processed_result = self._process_scan_result(ip_address, scan_result)
            
            logger.info(f"Scan completed for {ip_address}. Found {len(processed_result['open_ports'])} open ports")
            
            return processed_result
            
        except nmap.PortScannerError as e:
            error_msg = f"Nmap scanner error: {str(e)}"
            logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            error_msg = f"Unexpected error during scan: {str(e)}"
            logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg,
                'timestamp': datetime.now().isoformat()
            }
    
    def _process_scan_result(self, ip_address: str, scan_result: Dict) -> Dict[str, Any]:
        """Process raw nmap scan results into structured format"""
        try:
            result = {
                'success': True,
                'ip_address': ip_address,
                'timestamp': datetime.now().isoformat(),
                'scan_time': scan_result['nmap']['scanstats']['elapsed'],
                'open_ports': [],
                'host_info': {},
                'raw_result': scan_result
            }
            
            # Check if host was found in scan results
            if ip_address not in scan_result['scan']:
                result['success'] = False
                result['error'] = f"Host {ip_address} appears to be down or unreachable"
                return result
            
            host_data = scan_result['scan'][ip_address]
            
            # Extract host information
            result['host_info'] = {
                'state': host_data.get('status', {}).get('state', 'unknown'),
                'reason': host_data.get('status', {}).get('reason', 'unknown'),
                'hostname': host_data.get('hostnames', [{}])[0].get('name', '') if host_data.get('hostnames') else '',
                'os': self._extract_os_info(host_data),
                'vendor': host_data.get('vendor', {})
            }
            
            # Extract port information
            if 'tcp' in host_data:
                for port, port_data in host_data['tcp'].items():
                    if port_data['state'] == 'open':
                        port_info = {
                            'port': port,
                            'protocol': 'tcp',
                            'state': port_data['state'],
                            'service': port_data.get('name', 'unknown'),
                            'version': port_data.get('version', ''),
                            'product': port_data.get('product', ''),
                            'extrainfo': port_data.get('extrainfo', ''),
                            'conf': port_data.get('conf', ''),
                            'cpe': port_data.get('cpe', '')
                        }
                        result['open_ports'].append(port_info)
            
            # Sort ports by port number
            result['open_ports'].sort(key=lambda x: x['port'])
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing scan result: {e}")
            return {
                'success': False,
                'error': f"Error processing scan result: {str(e)}",
                'timestamp': datetime.now().isoformat()
            }
    
    def _extract_os_info(self, host_data: Dict) -> Dict[str, Any]:
        """Extract OS information from scan results"""
        os_info = {
            'name': '',
            'family': '',
            'generation': '',
            'type': '',
            'vendor': '',
            'accuracy': 0
        }
        
        try:
            if 'osmatch' in host_data and host_data['osmatch']:
                best_match = host_data['osmatch'][0]  # Get the best OS match
                os_info.update({
                    'name': best_match.get('name', ''),
                    'accuracy': int(best_match.get('accuracy', 0)),
                    'type': best_match.get('osclass', [{}])[0].get('type', '') if best_match.get('osclass') else '',
                    'vendor': best_match.get('osclass', [{}])[0].get('vendor', '') if best_match.get('osclass') else '',
                    'family': best_match.get('osclass', [{}])[0].get('osfamily', '') if best_match.get('osclass') else '',
                    'generation': best_match.get('osclass', [{}])[0].get('osgen', '') if best_match.get('osclass') else ''
                })
                
        except Exception as e:
            logger.warning(f"Error extracting OS info: {e}")
        
        return os_info
    
    def _validate_ip(self, ip_address: str) -> bool:
        """Validate IP address format"""
        try:
            socket.inet_aton(ip_address)
            return True
        except socket.error:
            return False
    
    def quick_scan(self, ip_address: str) -> Dict[str, Any]:
        """
        Perform a quick scan of common ports
        
        Args:
            ip_address: Target IP address
            
        Returns:
            Dictionary containing scan results
        """
        # Common ports to scan quickly
        common_ports = "21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080"
        
        return self.scan_host(ip_address, common_ports)
    
    def get_scanner_info(self) -> Dict[str, str]:
        """Get information about the nmap scanner"""
        try:
            return {
                'nmap_version': self.nm.nmap_version(),
                'scanner_info': str(self.nm),
                'available': True
            }
        except Exception as e:
            return {
                'error': str(e),
                'available': False
            }
