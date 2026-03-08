# Revelion Daemon

The local execution layer for [Revelion](https://app.revelion.ai) — AI-powered penetration testing.

The daemon runs on your machine, connects to the Revelion cloud brain via WebSocket, and manages Docker containers for sandboxed tool execution.

## Quick Install

### macOS / Linux

```bash
curl -fsSL https://raw.githubusercontent.com/RevelionAI/revelion-daemon/main/scripts/install.sh | sh -s -- YOUR_API_TOKEN
```

### Windows (PowerShell)

```powershell
$env:REVELION_TOKEN='YOUR_API_TOKEN'; irm https://raw.githubusercontent.com/RevelionAI/revelion-daemon/main/scripts/install.ps1 | iex
```

Find your API token at [app.revelion.ai/agents](https://app.revelion.ai/agents).

## Prerequisites

- **Docker** — The daemon uses Docker to run scan tools in isolated containers
  - [Docker Desktop](https://docs.docker.com/desktop/) (macOS/Windows)
  - [Docker Engine](https://docs.docker.com/engine/install/) (Linux)

## Manual Installation

Download the latest binary from [Releases](https://github.com/RevelionAI/revelion-daemon/releases), then:

```bash
# Authenticate
revelion auth YOUR_API_TOKEN

# Start the daemon
revelion start

# Check status
revelion status
```

## Commands

| Command | Description |
|---|---|
| `revelion auth <token>` | Save your API token |
| `revelion start` | Start the daemon |
| `revelion status` | Show configuration |
| `revelion version` | Print version |

## How It Works

1. You start the daemon on your machine
2. It connects to the Revelion brain via WebSocket
3. When you launch a scan, the brain sends commands to your daemon
4. The daemon spins up Docker containers and executes tools in a sandbox
5. Results stream back to the brain for AI analysis

## License

Proprietary — see [Revelion Terms of Service](https://app.revelion.ai/terms).
