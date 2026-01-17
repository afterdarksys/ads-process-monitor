# ADS Process Monitor

macOS Process Attack Visibility Tool - Part of the ADS macOS Security Suite.

## Features

- **Process Listing**: List all running processes with security-relevant details
- **Process Tree**: Visualize process hierarchies for tracing execution chains
- **Watch Mode**: Real-time monitoring for new process executions
- **Suspicious Detection**: Automatic flagging of potentially malicious processes
- **AI Analysis**: Multi-tier AI threat analysis (Rules → ONNX → Cloud)
- **JSON Output**: Machine-readable output for automation and integration
- **HTTP API**: Server mode for GUI console integration
- **License System**: Feature gating for Free/Pro/Enterprise tiers

## Installation

```bash
make build
sudo make install
```

## Usage

### List Processes

```bash
# Table output
ads-process-monitor list

# JSON output
ads-process-monitor list --output-json

# Filter by user
ads-process-monitor list --user root

# Show only suspicious processes
ads-process-monitor list --suspicious
```

### Process Tree

```bash
# Full tree from launchd (PID 1)
ads-process-monitor tree

# Tree from specific process
ads-process-monitor tree --pid 1234

# JSON output
ads-process-monitor tree --output-json
```

### AI-Powered Analysis

```bash
# Analyze a specific process
ads-process-monitor analyze --pid 1234

# Analyze all suspicious processes (default)
ads-process-monitor analyze

# Analyze all processes
ads-process-monitor analyze --all

# JSON output with full details
ads-process-monitor analyze --pid 1234 --output-json
```

### Watch Mode

```bash
# Watch for new processes
ads-process-monitor watch

# Custom poll interval (ms)
ads-process-monitor watch --interval 100

# JSON output (for piping to other tools)
ads-process-monitor watch --output-json
```

### Configuration

```bash
# Initialize config file
ads-process-monitor config init

# Show current config
ads-process-monitor config show

# View license info
ads-process-monitor license
```

### HTTP API Server

```bash
# Start server on default port (9001)
ads-process-monitor serve

# Custom port
ads-process-monitor serve --port 8080
```

#### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/info` | GET | Tool version and capabilities |
| `/processes` | GET | List all processes |
| `/tree` | GET | Process tree |
| `/suspicious` | GET | List suspicious processes only |

## AI Analysis Tiers

| Tier | Name | Description | License |
|------|------|-------------|---------|
| 1 | Rules | Rule-based detection, 15+ detection rules | Free |
| 2 | ONNX | On-device ML model inference | Pro+ |
| 3 | Cloud | Cloud AI analysis (Anthropic/OpenAI/OpenRouter) | Pro+ |

### Configuration File

Located at `~/.ads/process-monitor.json`:

```json
{
  "tiers": {
    "rules_enabled": true,
    "onnx_enabled": false,
    "cloud_enabled": false,
    "cloud_provider": "anthropic"
  },
  "api_keys": {
    "anthropic": "sk-ant-...",
    "openai": "sk-...",
    "openrouter": "sk-or-..."
  },
  "models": {
    "onnx_model_path": "~/.ads/models/process-classifier.onnx"
  },
  "analysis": {
    "confidence_threshold": 70,
    "auto_escalate": true,
    "escalate_threshold": 50
  }
}
```

## Suspicious Process Detection

Built-in rules detect:

| Rule ID | Name | Description | Severity |
|---------|------|-------------|----------|
| NET001 | Reverse Shell | /dev/tcp, nc -e patterns | 9 |
| NET002 | Network Tool | nc, socat, nmap, etc. | 7 |
| EXEC001 | Temp Execution | Running from /tmp | 6 |
| EXEC002 | Hidden Execution | Running from hidden file | 7 |
| EXEC003 | Downloads Execution | Running from Downloads | 5 |
| SCRIPT001 | Encoded Command | base64 decode in cmdline | 8 |
| SCRIPT002 | Long Encoded Arg | Suspiciously long argument | 6 |
| SCRIPT003 | Osascript | AppleScript execution | 5 |
| CRED001 | Keychain Access | security find-/dump- | 7 |
| CRED002 | SSH Key Access | Reading .ssh/id_* | 6 |
| PERSIST001 | LaunchAgent Mod | Writing to LaunchAgents | 8 |
| MASQ001 | Masquerading | Name doesn't match exe | 7 |
| CRYPTO001 | Cryptominer | Mining indicators | 6 |

## License Tiers

| Feature | Free | Pro | Enterprise |
|---------|------|-----|------------|
| Rules Analysis | ✓ | ✓ | ✓ |
| ONNX Analysis | - | ✓ | ✓ |
| Cloud Analysis | - | ✓ | ✓ |
| Realtime Monitoring | - | ✓ | ✓ |
| HTTP Server | - | ✓ | ✓ |
| Custom Rules | - | ✓ | ✓ |
| SIEM Integration | - | - | ✓ |
| API Access | - | - | ✓ |

## Integration

This tool is designed to integrate with:

1. **ADS Security Console GUI** - via HTTP API
2. **afterdark-darkd** - as a service plugin
3. **SIEM/SOAR** - via JSON output and webhooks

```bash
# Part of the ADS Security Suite
ads-process-monitor serve --port 9001  # Process visibility
ads-memory-forensics serve --port 9002  # Memory analysis
ads-supply-chain serve --port 9003      # Package monitoring
```

## License

Copyright (c) 2026 After Dark Systems. All rights reserved.
