# ESXiTri Enhanced - Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Step 1: Download and Deploy

```bash
# 1. Copy files to your ESXi host
scp ESXiTri_Enhanced.sh user@your-esxi-host:/tmp/
scp ai_analysis_module.py user@your-esxi-host:/tmp/
scp threat_intel_module.py user@your-esxi-host:/tmp/
scp esxitri_config.conf user@your-esxi-host:/tmp/

# 2. Set permissions
ssh user@your-esxi-host "chmod +x /tmp/ESXiTri_Enhanced.sh"
ssh user@your-esxi-host "chmod +x /tmp/ai_analysis_module.py"
ssh user@your-esxi-host "chmod +x /tmp/threat_intel_module.py"
```

### Step 2: Basic Configuration

Edit the configuration file for your environment:

```bash
# SSH to your ESXi host
ssh user@your-esxi-host

# Edit configuration
vi /tmp/esxitri_config.conf
```

**Minimum configuration:**
```bash
# Enable basic enhanced features
AI_ANALYSIS_ENABLED=true
ENHANCED_LOGGING=true
CHAIN_OF_CUSTODY=true

# Optional: Enable threat intelligence (requires API keys)
# THREAT_INTEL_ENABLED=true
# THREAT_INTEL_API_KEY="your_virustotal_api_key"
```

### Step 3: Run Enhanced Collection

```bash
# Basic enhanced collection
./ESXiTri_Enhanced.sh

# With real-time monitoring (every 30 seconds)
./ESXiTri_Enhanced.sh -r -i 30

# Full enhanced mode
./ESXiTri_Enhanced.sh --ai-analysis --chain-of-custody
```

### Step 4: Retrieve Results

```bash
# Download the enhanced archive
scp user@your-esxi-host:/tmp/ESXiTri_Enhanced_*.tar.gz ./

# Extract and view results
tar -xzf ESXiTri_Enhanced_*.tar.gz
cd ESXiTri_Enhanced_*
ls -la
```

## 📊 What You Get

### Enhanced Analysis Results:
- **AI Analysis**: Intelligent anomaly detection
- **Threat Intelligence**: Hash and IP reputation checks
- **Enhanced Logging**: Comprehensive audit trails
- **Executive Summary**: Management-ready reports
- **Technical Details**: Deep technical analysis

### Key Files to Review:
```bash
# Executive summary for management
cat enhanced_summary_report.txt

# AI analysis results
cat ai_analysis.log

# Threat intelligence findings
cat threat_analysis.log

# Chain of custody
cat audit_trail.log
```

## 🔧 Advanced Features

### Enable Threat Intelligence:
```bash
# Get free API keys from:
# - VirusTotal: https://www.virustotal.com/gui/join-us
# - AbuseIPDB: https://www.abuseipdb.com/api

# Edit configuration
vi /tmp/esxitri_config.conf

# Add your API keys
THREAT_INTEL_API_KEY="your_virustotal_api_key"
ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
```

### Enable SIEM Integration:
```bash
# For Splunk
SIEM_ENDPOINT="https://your-splunk:8088/services/collector/event"
SIEM_API_KEY="your_splunk_token"

# Run with SIEM integration
./ESXiTri_Enhanced.sh -s https://your-splunk:8088/services/collector/event
```

### Real-Time Monitoring:
```bash
# Monitor every 15 seconds
./ESXiTri_Enhanced.sh -r -i 15

# Monitor every 5 minutes
./ESXiTri_Enhanced.sh -r -i 300

# Stop monitoring (Ctrl+C)
```

## 🚨 Incident Response Mode

### Automated Response:
```bash
# Enable automated incident response
./ESXiTri_Enhanced.sh -a --ai-analysis

# This will:
# - Detect threats automatically
# - Isolate compromised VMs
# - Preserve evidence
# - Generate incident reports
```

### Manual Analysis:
```bash
# Run AI analysis on collected data
python3 ai_analysis_module.py /path/to/esxitri_data/

# Run threat intelligence analysis
python3 threat_intel_module.py /path/to/esxitri_data/
```

## 📈 Performance Tips

### For Large Environments:
```bash
# Enable parallel processing
PARALLEL_PROCESSING=true

# Set resource limits
RESOURCE_LIMIT_PERCENT=80

# Use configuration file
./ESXiTri_Enhanced.sh -c /tmp/esxitri_config.conf
```

### For Continuous Monitoring:
```bash
# Set up cron job for regular monitoring
crontab -e

# Add line for hourly monitoring
0 * * * * /tmp/ESXiTri_Enhanced.sh -r -i 300 --ai-analysis
```

## 🔍 Troubleshooting

### Common Issues:

**Permission Denied:**
```bash
chmod +x /tmp/ESXiTri_Enhanced.sh
```

**Python Not Found:**
```bash
# ESXi may not have Python, use basic mode
./ESXiTri_Enhanced.sh --no-ai-analysis
```

**API Errors:**
```bash
# Check internet connectivity
ping api.virustotal.com

# Verify API keys
cat /tmp/esxitri_config.conf
```

**Storage Full:**
```bash
# Check available space
df -h

# Clean up old collections
rm -rf /tmp/ESXiTri_*
```

## 📞 Quick Support

### Immediate Help:
1. **Check logs**: `cat /tmp/ESXiTri_Enhanced.log`
2. **Verify configuration**: `cat /tmp/esxitri_config.conf`
3. **Test basic functionality**: `./ESXiTri_Enhanced.sh --help`

### Common Commands:
```bash
# Show help
./ESXiTri_Enhanced.sh -h

# Verbose logging
./ESXiTri_Enhanced.sh -v

# Test configuration
./ESXiTri_Enhanced.sh --test-config

# Dry run (no actual collection)
./ESXiTri_Enhanced.sh --dry-run
```

## 🎯 Next Steps

### After Basic Deployment:
1. **Review Results**: Analyze the enhanced summary report
2. **Configure Alerts**: Set up SIEM integration for real-time alerts
3. **Customize Analysis**: Modify AI analysis parameters
4. **Scale Deployment**: Deploy across multiple ESXi hosts
5. **Integrate Workflows**: Connect with existing security tools

### Advanced Configuration:
- **Custom AI Models**: Train models on your environment
- **Threat Hunting**: Set up proactive threat hunting
- **Compliance**: Configure for regulatory requirements
- **Automation**: Integrate with SOAR platforms

---

**Ready to enhance your ESXi security? Start with the basic deployment and gradually enable advanced features!** 