# IoTVAS CLI - AI Agent Usage Guide

This CLI is designed to be used by AI agents for IoT device discovery and vulnerability assessment.

## Authentication

Before using any commands, configure your API key:

```bash
firmalyzercomiotvas config set --api-key YOUR_API_KEY
```

## Common Tasks

### 1. Detect IoT Device

When you have network scan data (SNMP, HTTP, FTP, Telnet banners, MAC address, hostname):

```bash
firmalyzercomiotvas devices detect --snmp "BANNER" --mac "MAC_ADDRESS" --json
```

### 2. List Known Devices

```bash
firmalyzercomiotvas devices list --json
```

### 3. Check Device Vulnerabilities

```bash
firmalyzercomiotvas devices get DEVICE_ID --json
```

### 4. Search for CVEs

```bash
firmalyzercomiotvas vulnerabilities search "keyword" --json
```

### 5. Get CVE Details

```bash
firmalyzercomiotvas vulnerabilities get CVE-2021-12345 --json
```

### 6. Analyze Firmware

```bash
firmalyzercomiotvas firmware analyze SHA256_HASH --json
firmalyzercomiotvas firmware report REPORT_ID --json
```

## JSON Output

All commands support `--json` flag for structured output suitable for parsing.

## Error Handling

- Exit code 0 = success
- Exit code 1 = error (check stderr for message)

## Rate Limits

IoTVAS API has rate limits. If you receive a 429 error, wait before retrying.

## Use Cases

- **Network Security Audits**: Scan network, detect devices, assess vulnerabilities
- **Firmware Validation**: Analyze firmware hashes before deployment
- **CVE Monitoring**: Search and track vulnerabilities for specific IoT devices
- **Device Inventory**: Maintain inventory of IoT devices with EOL status
