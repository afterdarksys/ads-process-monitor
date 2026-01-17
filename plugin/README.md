# ADS Process Monitor - darkd Plugin

This plugin integrates ads-process-monitor with afterdark-darkd, allowing it to run as a managed service within the security daemon.

## Features

When running as a darkd plugin:
- Managed lifecycle (start/stop/restart)
- Centralized configuration via darkd.yaml
- Event integration with daemon
- Health monitoring
- IPC via gRPC

## Building

```bash
cd plugin
go build -o ads-process-monitor-plugin .
```

## Installation

```bash
sudo cp ads-process-monitor-plugin /var/lib/afterdark-darkd/plugins/
sudo chmod +x /var/lib/afterdark-darkd/plugins/ads-process-monitor-plugin
```

## Configuration

In `/etc/afterdark-darkd/darkd.yaml`:

```yaml
plugins:
  ads-process-monitor:
    watch_interval_ms: 500      # Process polling interval
    enable_ai_analysis: true    # Enable AI-powered analysis
    alert_on_suspicious: true   # Emit events for suspicious processes
```

## Actions

The plugin supports these actions via darkd IPC:

### list
List all running processes.

```bash
darkdadm plugin exec ads-process-monitor list
darkdadm plugin exec ads-process-monitor list --params '{"user":"root"}'
darkdadm plugin exec ads-process-monitor list --params '{"suspicious":true}'
```

### tree
Get process tree.

```bash
darkdadm plugin exec ads-process-monitor tree
darkdadm plugin exec ads-process-monitor tree --params '{"pid":1234}'
```

### analyze
Run AI analysis on a process.

```bash
darkdadm plugin exec ads-process-monitor analyze --params '{"pid":1234}'
```

### status
Get plugin status.

```bash
darkdadm plugin exec ads-process-monitor status
```

## Events

The plugin emits these events to the daemon:

| Event | Description |
|-------|-------------|
| `suspicious_process` | New process matches suspicious patterns |
| `ai_detection` | AI analysis detected threat |

## Standalone Mode

The tool can also run standalone:

```bash
# CLI mode
ads-process-monitor list
ads-process-monitor analyze --pid 1234

# HTTP server mode
ads-process-monitor serve --port 9001
```

## Requirements

- afterdark-darkd v1.0.0+
- macOS 10.15+
- Go 1.21+
