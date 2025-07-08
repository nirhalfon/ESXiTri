#!/usr/bin/env python3
"""
ESXiTri Enhanced - AI Analysis Module
Provides AI-powered analysis capabilities for ESXi security triage
"""

import json
import hashlib
import re
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ESXiAIAnalyzer:
    """AI-powered analyzer for ESXi security data"""
    
    def __init__(self, config_file: str = None):
        self.config = self._load_config(config_file)
        self.anomaly_patterns = self._load_anomaly_patterns()
        self.threat_indicators = self._load_threat_indicators()
        self.analysis_results = {}
        
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from file"""
        default_config = {
            'confidence_threshold': 0.8,
            'enable_ml_analysis': True,
            'enable_behavioral_analysis': True,
            'enable_anomaly_detection': True,
            'model_path': '/tmp/esxitri_ai_models'
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    default_config.update(config)
            except Exception as e:
                logger.warning(f"Failed to load config file: {e}")
                
        return default_config
    
    def _load_anomaly_patterns(self) -> Dict[str, List[str]]:
        """Load predefined anomaly patterns"""
        return {
            'suspicious_processes': [
                r'crypto.*miner',
                r'backdoor',
                r'trojan',
                r'malware',
                r'suspicious',
                r'[a-z]{1,2}\.exe',  # Short executable names
                r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'  # IP-like names
            ],
            'suspicious_network': [
                r':22$',  # SSH
                r':23$',  # Telnet
                r':3389$',  # RDP
                r':445$',  # SMB
                r':1433$',  # MSSQL
                r':3306$',  # MySQL
                r':5432$',  # PostgreSQL
                r':6379$',  # Redis
                r':27017$'  # MongoDB
            ],
            'suspicious_files': [
                r'\.(exe|dll|bat|cmd|ps1|vbs|js)$',
                r'\.(crypto|miner|backdoor|trojan)$',
                r'^[a-z]{1,3}$'  # Very short filenames
            ]
        }
    
    def _load_threat_indicators(self) -> Dict[str, List[str]]:
        """Load known threat indicators"""
        return {
            'malicious_ips': [
                '10.0.0.1',
                '192.168.1.1',
                '127.0.0.1'
            ],
            'malicious_domains': [
                'malicious.example.com',
                'suspicious.domain.com'
            ],
            'malicious_hashes': [
                # Add known malicious file hashes here
            ]
        }
    
    def analyze_process_list(self, process_data: str) -> Dict[str, Any]:
        """Analyze process list for anomalies"""
        results = {
            'anomalies': [],
            'suspicious_processes': [],
            'high_memory_processes': [],
            'unusual_pids': [],
            'confidence_score': 0.0
        }
        
        try:
            lines = process_data.strip().split('\n')
            anomaly_count = 0
            total_processes = len(lines)
            
            for line in lines:
                if not line.strip():
                    continue
                    
                # Check for suspicious process names
                for pattern in self.anomaly_patterns['suspicious_processes']:
                    if re.search(pattern, line, re.IGNORECASE):
                        results['suspicious_processes'].append({
                            'process': line,
                            'pattern': pattern,
                            'confidence': 0.9
                        })
                        anomaly_count += 1
                
                # Check for unusual PIDs (very low numbers)
                pid_match = re.search(r'^\s*(\d+)', line)
                if pid_match:
                    pid = int(pid_match.group(1))
                    if pid < 1000 and pid != 1:
                        results['unusual_pids'].append({
                            'process': line,
                            'pid': pid,
                            'confidence': 0.7
                        })
                        anomaly_count += 1
                
                # Check for high memory usage (simplified)
                if 'MB' in line or 'GB' in line:
                    memory_match = re.search(r'(\d+)\s*(MB|GB)', line)
                    if memory_match:
                        memory_value = int(memory_match.group(1))
                        memory_unit = memory_match.group(2)
                        if memory_unit == 'GB' or (memory_unit == 'MB' and memory_value > 1000):
                            results['high_memory_processes'].append({
                                'process': line,
                                'memory': f"{memory_value}{memory_unit}",
                                'confidence': 0.6
                            })
            
            # Calculate confidence score
            if total_processes > 0:
                results['confidence_score'] = min(1.0, anomaly_count / total_processes)
            
            results['anomalies'] = (
                results['suspicious_processes'] + 
                results['unusual_pids'] + 
                results['high_memory_processes']
            )
            
        except Exception as e:
            logger.error(f"Error analyzing process list: {e}")
            
        return results
    
    def analyze_network_connections(self, network_data: str) -> Dict[str, Any]:
        """Analyze network connections for anomalies"""
        results = {
            'anomalies': [],
            'suspicious_connections': [],
            'unusual_ports': [],
            'external_connections': [],
            'confidence_score': 0.0
        }
        
        try:
            lines = network_data.strip().split('\n')
            anomaly_count = 0
            total_connections = len(lines)
            
            for line in lines:
                if not line.strip():
                    continue
                
                # Check for suspicious ports
                for pattern in self.anomaly_patterns['suspicious_network']:
                    if re.search(pattern, line):
                        results['unusual_ports'].append({
                            'connection': line,
                            'pattern': pattern,
                            'confidence': 0.8
                        })
                        anomaly_count += 1
                
                # Check for external connections
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    ip = ip_match.group(1)
                    if not ip.startswith(('10.', '192.168.', '172.', '127.')):
                        results['external_connections'].append({
                            'connection': line,
                            'ip': ip,
                            'confidence': 0.7
                        })
                        anomaly_count += 1
                
                # Check for known malicious IPs
                for malicious_ip in self.threat_indicators['malicious_ips']:
                    if malicious_ip in line:
                        results['suspicious_connections'].append({
                            'connection': line,
                            'malicious_ip': malicious_ip,
                            'confidence': 0.95
                        })
                        anomaly_count += 1
            
            # Calculate confidence score
            if total_connections > 0:
                results['confidence_score'] = min(1.0, anomaly_count / total_connections)
            
            results['anomalies'] = (
                results['suspicious_connections'] + 
                results['unusual_ports'] + 
                results['external_connections']
            )
            
        except Exception as e:
            logger.error(f"Error analyzing network connections: {e}")
            
        return results
    
    def analyze_file_system(self, file_data: str) -> Dict[str, Any]:
        """Analyze file system for anomalies"""
        results = {
            'anomalies': [],
            'suspicious_files': [],
            'hidden_files': [],
            'recent_modifications': [],
            'confidence_score': 0.0
        }
        
        try:
            lines = file_data.strip().split('\n')
            anomaly_count = 0
            total_files = len(lines)
            
            for line in lines:
                if not line.strip():
                    continue
                
                # Check for suspicious file patterns
                for pattern in self.anomaly_patterns['suspicious_files']:
                    if re.search(pattern, line, re.IGNORECASE):
                        results['suspicious_files'].append({
                            'file': line,
                            'pattern': pattern,
                            'confidence': 0.8
                        })
                        anomaly_count += 1
                
                # Check for hidden files
                if '/.' in line or line.strip().startswith('.'):
                    results['hidden_files'].append({
                        'file': line,
                        'confidence': 0.6
                    })
                    anomaly_count += 1
                
                # Check for recent modifications (last 24 hours)
                time_match = re.search(r'(\d{4}-\d{2}-\d{2})', line)
                if time_match:
                    file_date = datetime.strptime(time_match.group(1), '%Y-%m-%d')
                    if file_date > datetime.now() - timedelta(days=1):
                        results['recent_modifications'].append({
                            'file': line,
                            'date': time_match.group(1),
                            'confidence': 0.5
                        })
                        anomaly_count += 1
            
            # Calculate confidence score
            if total_files > 0:
                results['confidence_score'] = min(1.0, anomaly_count / total_files)
            
            results['anomalies'] = (
                results['suspicious_files'] + 
                results['hidden_files'] + 
                results['recent_modifications']
            )
            
        except Exception as e:
            logger.error(f"Error analyzing file system: {e}")
            
        return results
    
    def analyze_memory_usage(self, memory_data: str) -> Dict[str, Any]:
        """Analyze memory usage for anomalies"""
        results = {
            'anomalies': [],
            'high_memory_usage': False,
            'memory_leak_suspected': False,
            'confidence_score': 0.0
        }
        
        try:
            # Simple memory analysis
            if 'MB' in memory_data or 'GB' in memory_data:
                # Look for high memory usage patterns
                if '90%' in memory_data or '95%' in memory_data:
                    results['high_memory_usage'] = True
                    results['confidence_score'] = 0.8
                    results['anomalies'].append({
                        'type': 'high_memory_usage',
                        'description': 'Memory usage above 90%',
                        'confidence': 0.8
                    })
            
        except Exception as e:
            logger.error(f"Error analyzing memory usage: {e}")
            
        return results
    
    def correlate_events(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate multiple analysis results for higher confidence"""
        correlation_results = {
            'correlated_anomalies': [],
            'threat_score': 0.0,
            'recommendations': []
        }
        
        try:
            total_anomalies = 0
            high_confidence_anomalies = 0
            
            # Count anomalies across all analyses
            for analysis_type, results in analysis_results.items():
                if 'anomalies' in results:
                    total_anomalies += len(results['anomalies'])
                    high_confidence_anomalies += len([
                        a for a in results['anomalies'] 
                        if a.get('confidence', 0) > 0.8
                    ])
            
            # Calculate overall threat score
            if total_anomalies > 0:
                correlation_results['threat_score'] = min(1.0, high_confidence_anomalies / total_anomalies)
            
            # Generate recommendations based on threat score
            if correlation_results['threat_score'] > 0.8:
                correlation_results['recommendations'].append({
                    'priority': 'HIGH',
                    'action': 'Immediate investigation required',
                    'description': 'High confidence anomalies detected'
                })
            elif correlation_results['threat_score'] > 0.5:
                correlation_results['recommendations'].append({
                    'priority': 'MEDIUM',
                    'action': 'Investigate suspicious activities',
                    'description': 'Medium confidence anomalies detected'
                })
            else:
                correlation_results['recommendations'].append({
                    'priority': 'LOW',
                    'action': 'Monitor for changes',
                    'description': 'Low threat score, continue monitoring'
                })
            
        except Exception as e:
            logger.error(f"Error correlating events: {e}")
            
        return correlation_results
    
    def generate_ai_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate AI analysis report"""
        report = []
        report.append("=== ESXiTri AI Analysis Report ===")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report.append("")
        
        # Summary
        total_anomalies = sum(
            len(results.get('anomalies', [])) 
            for results in analysis_results.values()
        )
        report.append(f"Total Anomalies Detected: {total_anomalies}")
        report.append("")
        
        # Detailed analysis
        for analysis_type, results in analysis_results.items():
            report.append(f"--- {analysis_type.upper()} ANALYSIS ---")
            
            if 'anomalies' in results:
                for anomaly in results['anomalies']:
                    report.append(f"  - {anomaly.get('description', str(anomaly))}")
                    report.append(f"    Confidence: {anomaly.get('confidence', 0):.2f}")
            
            if 'confidence_score' in results:
                report.append(f"  Overall Confidence: {results['confidence_score']:.2f}")
            
            report.append("")
        
        # Recommendations
        if 'correlation' in analysis_results:
            report.append("--- RECOMMENDATIONS ---")
            for rec in analysis_results['correlation'].get('recommendations', []):
                report.append(f"  [{rec['priority']}] {rec['action']}")
                report.append(f"    {rec['description']}")
            report.append("")
        
        return "\n".join(report)
    
    def save_analysis_results(self, results: Dict[str, Any], output_file: str):
        """Save analysis results to file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"Analysis results saved to {output_file}")
        except Exception as e:
            logger.error(f"Error saving analysis results: {e}")

def main():
    """Main function for standalone execution"""
    if len(sys.argv) < 2:
        print("Usage: python3 ai_analysis_module.py <data_directory>")
        sys.exit(1)
    
    data_dir = sys.argv[1]
    analyzer = ESXiAIAnalyzer()
    
    # Analyze available data files
    analysis_results = {}
    
    # Process analysis
    process_file = os.path.join(data_dir, 'Memory', 'Process_List.txt')
    if os.path.exists(process_file):
        with open(process_file, 'r') as f:
            process_data = f.read()
        analysis_results['process_analysis'] = analyzer.analyze_process_list(process_data)
    
    # Network analysis
    network_file = os.path.join(data_dir, 'Network', 'Active_Network_Connections.txt')
    if os.path.exists(network_file):
        with open(network_file, 'r') as f:
            network_data = f.read()
        analysis_results['network_analysis'] = analyzer.analyze_network_connections(network_data)
    
    # File system analysis
    filesystem_file = os.path.join(data_dir, 'FileSystem', 'root_Dir_Listing.txt')
    if os.path.exists(filesystem_file):
        with open(filesystem_file, 'r') as f:
            filesystem_data = f.read()
        analysis_results['filesystem_analysis'] = analyzer.analyze_file_system(filesystem_data)
    
    # Correlate results
    analysis_results['correlation'] = analyzer.correlate_events(analysis_results)
    
    # Generate report
    report = analyzer.generate_ai_report(analysis_results)
    
    # Save results
    output_file = os.path.join(data_dir, 'ai_analysis_results.json')
    analyzer.save_analysis_results(analysis_results, output_file)
    
    # Print report
    print(report)
    
    # Save report to file
    report_file = os.path.join(data_dir, 'ai_analysis_report.txt')
    with open(report_file, 'w') as f:
        f.write(report)
    
    print(f"\nAI analysis completed. Results saved to {output_file}")
    print(f"Report saved to {report_file}")

if __name__ == "__main__":
    main() 