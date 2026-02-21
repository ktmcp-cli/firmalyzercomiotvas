> "Six months ago, everyone was talking about MCPs. And I was like, screw MCPs. Every MCP would be better as a CLI."
>
> — [Peter Steinberger](https://twitter.com/steipete), Founder of OpenClaw
> [Watch on YouTube (~2:39:00)](https://www.youtube.com/@lexfridman) | [Lex Fridman Podcast #491](https://lexfridman.com/peter-steinberger/)

# IoTVAS CLI

A production-ready command-line interface for the [Firmalyzer IoTVAS](https://firmalyzer.com/iotvas-api/) API. Detect IoT devices, assess vulnerabilities, and analyze firmware directly from your terminal.

> **Disclaimer**: This is an unofficial CLI tool and is not affiliated with, endorsed by, or supported by Firmalyzer.

## Features

- **Device Detection** — Identify IoT devices from network banners (SNMP, FTP, Telnet, HTTP, UPnP, MAC)
- **Vulnerability Assessment** — List, search, and get CVE details for IoT devices
- **Firmware Analysis** — Analyze firmware hashes and retrieve security reports
- **API Key Auth** — Secure authentication with x-api-key header
- **JSON output** — All commands support `--json` for scripting and piping
- **Colorized output** — Clean, readable terminal output with chalk

## Why CLI > MCP

MCP servers are complex, stateful, and require a running server process. A CLI is:

- **Simpler** — Just a binary you call directly
- **Composable** — Pipe output to `jq`, `grep`, `awk`, and other tools
- **Scriptable** — Use in shell scripts, CI/CD pipelines, cron jobs
- **Debuggable** — See exactly what's happening with `--json` flag
- **AI-friendly** — AI agents can call CLIs just as easily as MCPs, with less overhead

## Installation

```bash
npm install -g @ktmcp-cli/firmalyzercomiotvas
```

## Authentication Setup

### 1. Get an API Key

1. Visit [firmalyzer.com](https://firmalyzer.com/iotvas-api/)
2. Register for an API key
3. Copy your API key

### 2. Configure the CLI

```bash
firmalyzercomiotvas config set --api-key YOUR_API_KEY
```

### 3. Verify

```bash
firmalyzercomiotvas config show
```

## Commands

### Configuration

```bash
# Set API key
firmalyzercomiotvas config set --api-key <key>

# Show current config
firmalyzercomiotvas config show
```

### Device Detection

```bash
# Detect device from banners
firmalyzercomiotvas devices detect --snmp "Linux 3.10.0" --mac "00:11:22:33:44:55"
firmalyzercomiotvas devices detect --http "Server: nginx/1.14.0" --hostname "camera-01"
firmalyzercomiotvas devices detect --telnet "Welcome to Router" --ftp "220 FTP Server ready"

# List detected devices
firmalyzercomiotvas devices list
firmalyzercomiotvas devices list --limit 20

# Get specific device
firmalyzercomiotvas devices get <device-id>
```

### Vulnerabilities

```bash
# List vulnerabilities
firmalyzercomiotvas vulnerabilities list
firmalyzercomiotvas vulnerabilities list --limit 100

# Get CVE details
firmalyzercomiotvas vulnerabilities get CVE-2021-12345

# Search vulnerabilities
firmalyzercomiotvas vulnerabilities search "router"
```

### Firmware Analysis

```bash
# Analyze firmware by hash
firmalyzercomiotvas firmware analyze <sha256-hash>

# Get firmware report
firmalyzercomiotvas firmware report <report-id>

# List all reports
firmalyzercomiotvas firmware list-reports
firmalyzercomiotvas firmware list-reports --limit 50
```

## JSON Output

All commands support `--json` for machine-readable output:

```bash
# Get all devices as JSON
firmalyzercomiotvas devices list --json

# Pipe to jq for filtering
firmalyzercomiotvas devices list --json | jq '.[] | select(.eol_status == "EOL")'

# Search vulnerabilities and format
firmalyzercomiotvas vulnerabilities search "IoT" --json | jq '.[] | {cve: .cve_id, severity: .severity}'
```

## Examples

### Detect a device from network scan

```bash
# After scanning a device on your network
firmalyzercomiotvas devices detect \
  --snmp "Linux 2.6.32" \
  --http "Server: lighttpd/1.4.28" \
  --mac "A0:B1:C2:D3:E4:F5" \
  --hostname "ipcam-lobby"
```

### Find high-severity vulnerabilities

```bash
# List all vulnerabilities and filter
firmalyzercomiotvas vulnerabilities list --json | jq '.[] | select(.severity == "CRITICAL")'
```

### Analyze firmware before deployment

```bash
# Get firmware hash (SHA256)
sha256sum firmware.bin

# Analyze it
firmalyzercomiotvas firmware analyze <hash>

# Check the report
firmalyzercomiotvas firmware report <report-id> --json
```

## Contributing

Issues and pull requests are welcome at [github.com/ktmcp-cli/firmalyzercomiotvas](https://github.com/ktmcp-cli/firmalyzercomiotvas).

## License

MIT — see [LICENSE](LICENSE) for details.

---

Part of the [KTMCP CLI](https://killthemcp.com) project — replacing MCPs with simple, composable CLIs.


---

## Support KTMCP

If you find this CLI useful, we'd greatly appreciate your support! Share your experience on:
- Reddit
- Twitter/X
- Hacker News

**Incentive:** Users who can demonstrate that their support/advocacy helped advance KTMCP will have their feature requests and issues prioritized.

Just be mindful - these are real accounts and real communities. Authentic mentions and genuine recommendations go a long way!

## Support This Project

If you find this CLI useful, we'd appreciate support across Reddit, Twitter, Hacker News, or Moltbook. Please be mindful - these are real community accounts. Contributors who can demonstrate their support helped advance KTMCP will have their PRs and feature requests prioritized.
