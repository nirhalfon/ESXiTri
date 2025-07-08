#!/usr/bin/env python3
"""
ESXiTri Enhanced - Threat Intelligence Module
Provides threat intelligence lookup capabilities for ESXi security triage
"""

import json
import hashlib
import requests
import time
import os
import sys
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatIntelligenceEngine:
    """Threat intelligence engine for ESXi security analysis"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.api_keys = self.config.get('api_keys', {})
        self.cache = {}
        self.results = {}
        
        # Initialize API endpoints
        self.apis = {
            'virustotal': {
                'base_url': 'https://www.virustotal.com/v3',
                'api_key': self.api_keys.get('virustotal'),
                'enabled': bool(self.api_keys.get('virustotal'))
            },
            'abuseipdb': {
                'base_url': 'https://api.abuseipdb.com/api/v2',
                'api_key': self.api_keys.get('abuseipdb'),
                'enabled': bool(self.api_keys.get('abuseipdb'))
            },
            'alienvault': {
                'base_url': 'https://otx.alienvault.com/api/v1',
                'api_key': self.api_keys.get('alienvault'),
                'enabled': bool(self.api_keys.get('alienvault'))
            },
            'threatfox': {
                'base_url': 'https://threatfox-api.abuse.ch/api/v1',
                'api_key': None,  # No API key required
                'enabled': True
            }
        }
    
    def check_hash_reputation(self, file_hash: str) -> Dict[str, Any]:
        """Check file hash against threat intelligence databases"""
        results = {
            'hash': file_hash,
            'reputation': 'unknown',
            'confidence': 0.0,
            'sources': [],
            'details': {}
        }
        
        try:
            # VirusTotal hash check
            if self.apis['virustotal']['enabled']:
                vt_result = self._check_virustotal_hash(file_hash)
                if vt_result:
                    results['sources'].append('virustotal')
                    results['details']['virustotal'] = vt_result
                    
                    # Update overall reputation
                    if vt_result.get('malicious_votes', 0) > 0:
                        results['reputation'] = 'malicious'
                        results['confidence'] = min(1.0, vt_result['malicious_votes'] / 100)
            
            # ThreatFox hash check
            if self.apis['threatfox']['enabled']:
                tf_result = self._check_threatfox_hash(file_hash)
                if tf_result:
                    results['sources'].append('threatfox')
                    results['details']['threatfox'] = tf_result
                    
                    if tf_result.get('malware_type'):
                        results['reputation'] = 'malicious'
                        results['confidence'] = max(results['confidence'], 0.8)
            
            # Cache result
            self.cache[f"hash_{file_hash}"] = results
            
        except Exception as e:
            logger.error(f"Error checking hash reputation for {file_hash}: {e}")
            results['error'] = str(e)
        
        return results
    
    def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Check IP address against threat intelligence databases"""
        results = {
            'ip': ip_address,
            'reputation': 'unknown',
            'confidence': 0.0,
            'sources': [],
            'details': {}
        }
        
        try:
            # AbuseIPDB check
            if self.apis['abuseipdb']['enabled']:
                abuse_result = self._check_abuseipdb_ip(ip_address)
                if abuse_result:
                    results['sources'].append('abuseipdb')
                    results['details']['abuseipdb'] = abuse_result
                    
                    if abuse_result.get('abuse_confidence_score', 0) > 50:
                        results['reputation'] = 'malicious'
                        results['confidence'] = abuse_result['abuse_confidence_score'] / 100
            
            # AlienVault OTX check
            if self.apis['alienvault']['enabled']:
                otx_result = self._check_alienvault_ip(ip_address)
                if otx_result:
                    results['sources'].append('alienvault')
                    results['details']['alienvault'] = otx_result
                    
                    if otx_result.get('pulse_count', 0) > 0:
                        results['reputation'] = 'suspicious'
                        results['confidence'] = max(results['confidence'], 0.6)
            
            # Cache result
            self.cache[f"ip_{ip_address}"] = results
            
        except Exception as e:
            logger.error(f"Error checking IP reputation for {ip_address}: {e}")
            results['error'] = str(e)
        
        return results
    
    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain against threat intelligence databases"""
        results = {
            'domain': domain,
            'reputation': 'unknown',
            'confidence': 0.0,
            'sources': [],
            'details': {}
        }
        
        try:
            # AlienVault OTX domain check
            if self.apis['alienvault']['enabled']:
                otx_result = self._check_alienvault_domain(domain)
                if otx_result:
                    results['sources'].append('alienvault')
                    results['details']['alienvault'] = otx_result
                    
                    if otx_result.get('pulse_count', 0) > 0:
                        results['reputation'] = 'suspicious'
                        results['confidence'] = max(results['confidence'], 0.6)
            
            # Cache result
            self.cache[f"domain_{domain}"] = results
            
        except Exception as e:
            logger.error(f"Error checking domain reputation for {domain}: {e}")
            results['error'] = str(e)
        
        return results
    
    def _check_virustotal_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Check hash with VirusTotal API"""
        try:
            headers = {
                'x-apikey': self.apis['virustotal']['api_key']
            }
            
            url = f"{self.apis['virustotal']['base_url']}/files/{file_hash}"
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'malicious_votes': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0),
                    'total_votes': sum(data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).values()),
                    'file_type': data.get('data', {}).get('attributes', {}).get('type_description', 'Unknown'),
                    'file_size': data.get('data', {}).get('attributes', {}).get('size', 0)
                }
            elif response.status_code == 404:
                return {'status': 'not_found'}
            else:
                logger.warning(f"VirusTotal API error: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error calling VirusTotal API: {e}")
            return None
    
    def _check_abuseipdb_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP with AbuseIPDB API"""
        try:
            headers = {
                'Key': self.apis['abuseipdb']['api_key'],
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90
            }
            
            url = f"{self.apis['abuseipdb']['base_url']}/check"
            response = requests.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'abuse_confidence_score': data.get('data', {}).get('abuseConfidenceScore', 0),
                    'country_code': data.get('data', {}).get('countryCode', 'Unknown'),
                    'usage_type': data.get('data', {}).get('usageType', 'Unknown'),
                    'total_reports': data.get('data', {}).get('totalReports', 0)
                }
            else:
                logger.warning(f"AbuseIPDB API error: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error calling AbuseIPDB API: {e}")
            return None
    
    def _check_alienvault_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP with AlienVault OTX API"""
        try:
            headers = {}
            if self.apis['alienvault']['api_key']:
                headers['X-OTX-API-KEY'] = self.apis['alienvault']['api_key']
            
            url = f"{self.apis['alienvault']['base_url']}/indicators/IPv4/{ip_address}/general"
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'country_name': data.get('country_name', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'reputation': data.get('reputation', 0)
                }
            else:
                logger.warning(f"AlienVault API error: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error calling AlienVault API: {e}")
            return None
    
    def _check_alienvault_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check domain with AlienVault OTX API"""
        try:
            headers = {}
            if self.apis['alienvault']['api_key']:
                headers['X-OTX-API-KEY'] = self.apis['alienvault']['api_key']
            
            url = f"{self.apis['alienvault']['base_url']}/indicators/domain/{domain}/general"
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'whois': data.get('whois', 'Unknown'),
                    'reputation': data.get('reputation', 0)
                }
            else:
                logger.warning(f"AlienVault domain API error: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error calling AlienVault domain API: {e}")
            return None
    
    def _check_threatfox_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Check hash with ThreatFox API"""
        try:
            payload = {
                "query": "search_hash",
                "hash": file_hash
            }
            
            url = self.apis['threatfox']['base_url']
            response = requests.post(url, json=payload, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok' and data.get('data'):
                    malware_info = data['data'][0]
                    return {
                        'malware_type': malware_info.get('malware_type', 'Unknown'),
                        'malware_family': malware_info.get('malware_family', 'Unknown'),
                        'first_seen': malware_info.get('first_seen', 'Unknown'),
                        'confidence': malware_info.get('confidence_level', 0)
                    }
                else:
                    return {'status': 'not_found'}
            else:
                logger.warning(f"ThreatFox API error: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error calling ThreatFox API: {e}")
            return None
    
    def analyze_esxitri_data(self, data_directory: str) -> Dict[str, Any]:
        """Analyze ESXiTri collected data for threat intelligence"""
        analysis_results = {
            'hashes_checked': [],
            'ips_checked': [],
            'domains_checked': [],
            'threats_found': [],
            'summary': {}
        }
        
        try:
            # Check file hashes
            hash_files = [
                os.path.join(data_directory, 'FileSystem', 'root_MD5_Hashes.txt'),
                os.path.join(data_directory, 'FileSystem', 'bin_MD5_Hashes.txt'),
                os.path.join(data_directory, 'FileSystem', 'tmp_MD5_Hashes.txt')
            ]
            
            for hash_file in hash_files:
                if os.path.exists(hash_file):
                    with open(hash_file, 'r') as f:
                        for line in f:
                            parts = line.strip().split()
                            if len(parts) >= 2:
                                file_hash = parts[0]
                                file_path = ' '.join(parts[1:])
                                
                                result = self.check_hash_reputation(file_hash)
                                analysis_results['hashes_checked'].append({
                                    'hash': file_hash,
                                    'file': file_path,
                                    'result': result
                                })
                                
                                if result['reputation'] == 'malicious':
                                    analysis_results['threats_found'].append({
                                        'type': 'malicious_file',
                                        'hash': file_hash,
                                        'file': file_path,
                                        'confidence': result['confidence']
                                    })
            
            # Check network connections for IPs
            network_file = os.path.join(data_directory, 'Network', 'Active_Network_Connections.txt')
            if os.path.exists(network_file):
                with open(network_file, 'r') as f:
                    content = f.read()
                    # Extract IP addresses using regex
                    import re
                    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                    ips = re.findall(ip_pattern, content)
                    
                    for ip in set(ips):  # Remove duplicates
                        if not ip.startswith(('127.', '0.', '255.')):  # Skip local/broadcast IPs
                            result = self.check_ip_reputation(ip)
                            analysis_results['ips_checked'].append({
                                'ip': ip,
                                'result': result
                            })
                            
                            if result['reputation'] == 'malicious':
                                analysis_results['threats_found'].append({
                                    'type': 'malicious_ip',
                                    'ip': ip,
                                    'confidence': result['confidence']
                                })
            
            # Generate summary
            analysis_results['summary'] = {
                'total_hashes_checked': len(analysis_results['hashes_checked']),
                'total_ips_checked': len(analysis_results['ips_checked']),
                'total_threats_found': len(analysis_results['threats_found']),
                'malicious_files': len([t for t in analysis_results['threats_found'] if t['type'] == 'malicious_file']),
                'malicious_ips': len([t for t in analysis_results['threats_found'] if t['type'] == 'malicious_ip'])
            }
            
        except Exception as e:
            logger.error(f"Error analyzing ESXiTri data: {e}")
            analysis_results['error'] = str(e)
        
        return analysis_results
    
    def generate_threat_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate threat intelligence report"""
        report = []
        report.append("=== ESXiTri Threat Intelligence Report ===")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report.append("")
        
        # Summary
        summary = analysis_results.get('summary', {})
        report.append("--- SUMMARY ---")
        report.append(f"Total hashes checked: {summary.get('total_hashes_checked', 0)}")
        report.append(f"Total IPs checked: {summary.get('total_ips_checked', 0)}")
        report.append(f"Total threats found: {summary.get('total_threats_found', 0)}")
        report.append(f"Malicious files: {summary.get('malicious_files', 0)}")
        report.append(f"Malicious IPs: {summary.get('malicious_ips', 0)}")
        report.append("")
        
        # Threats found
        threats = analysis_results.get('threats_found', [])
        if threats:
            report.append("--- THREATS DETECTED ---")
            for threat in threats:
                if threat['type'] == 'malicious_file':
                    report.append(f"  MALICIOUS FILE:")
                    report.append(f"    Hash: {threat['hash']}")
                    report.append(f"    File: {threat['file']}")
                    report.append(f"    Confidence: {threat['confidence']:.2f}")
                elif threat['type'] == 'malicious_ip':
                    report.append(f"  MALICIOUS IP:")
                    report.append(f"    IP: {threat['ip']}")
                    report.append(f"    Confidence: {threat['confidence']:.2f}")
                report.append("")
        else:
            report.append("--- NO THREATS DETECTED ---")
            report.append("No malicious indicators found in the analyzed data.")
            report.append("")
        
        # Recommendations
        report.append("--- RECOMMENDATIONS ---")
        if threats:
            report.append("  [HIGH] Investigate all detected threats immediately")
            report.append("  [MEDIUM] Review network connections to suspicious IPs")
            report.append("  [MEDIUM] Analyze file system for additional indicators")
        else:
            report.append("  [LOW] Continue monitoring for new threats")
            report.append("  [LOW] Review analysis results for false negatives")
        
        report.append("")
        report.append("Report generated by ESXiTri Enhanced Threat Intelligence Module")
        
        return "\n".join(report)
    
    def save_results(self, results: Dict[str, Any], output_file: str):
        """Save threat intelligence results to file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"Threat intelligence results saved to {output_file}")
        except Exception as e:
            logger.error(f"Error saving threat intelligence results: {e}")

def main():
    """Main function for standalone execution"""
    if len(sys.argv) < 2:
        print("Usage: python3 threat_intel_module.py <data_directory> [config_file]")
        sys.exit(1)
    
    data_dir = sys.argv[1]
    config_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Load configuration
    config = {}
    if config_file and os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except Exception as e:
            logger.error(f"Error loading config file: {e}")
    
    # Initialize threat intelligence engine
    ti_engine = ThreatIntelligenceEngine(config)
    
    # Analyze ESXiTri data
    print("Analyzing ESXiTri data for threat intelligence...")
    results = ti_engine.analyze_esxitri_data(data_dir)
    
    # Generate report
    report = ti_engine.generate_threat_report(results)
    
    # Save results
    output_file = os.path.join(data_dir, 'threat_intelligence_results.json')
    ti_engine.save_results(results, output_file)
    
    # Print report
    print(report)
    
    # Save report to file
    report_file = os.path.join(data_dir, 'threat_intelligence_report.txt')
    with open(report_file, 'w') as f:
        f.write(report)
    
    print(f"\nThreat intelligence analysis completed.")
    print(f"Results saved to {output_file}")
    print(f"Report saved to {report_file}")

if __name__ == "__main__":
    main() 