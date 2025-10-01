# 🌟 OpenAPI MCP Bridge

> 🚀 Transform any OpenAPI/REST API into MCP tools instantly!

A lightweight, single-file MCP (Model Context Protocol) server that automatically converts OpenAPI specifications into Claude-compatible tools. Perfect for integrating any REST API with Claude Code or other MCP clients.

## ✨ Features

- 🔄 **Auto-discovery**: Automatically converts OpenAPI endpoints into MCP tools
- 🛡️ **Error resilient**: Graceful handling of unreachable APIs with degraded mode
- 📋 **Detailed logging**: Shows all discovered endpoints and proxy destinations
- 🌐 **Format flexible**: Supports both JSON and YAML OpenAPI specs
- ⚡ **Single file**: Just one Python file - easy to deploy anywhere
- 🔧 **Zero config**: Works out of the box with any valid OpenAPI URL
- 🎯 **Flexible API targeting**: Override API base URL independently from OpenAPI docs
- 🔐 **Multi-auth support**: Bearer, API Key, and Basic authentication
- 📡 **SSE streaming**: Server-Sent Events support for real-time connections
- 🔍 **Debug mode**: Verbose logging for troubleshooting
- 🛣️ **Context paths**: Deploy under custom URL paths
- 🌍 **Network resilient**: Automatic fallback for local network compatibility

## 🚀 Quick Start

### 📦 Installation

```bash
# Clone or download the script
# create your virtualenv
python -m venv venv
# install all dependencies
pip install -r requirements.txt
```

### 🎯 Basic Usage

```bash
# Start with any OpenAPI URL
python openapi_mcp_min.py https://petstore.swagger.io/v2/swagger.json

# Or with a local API
python openapi_mcp_min.py http://localhost:8080/api-docs

# Custom port
PORT=7744 python openapi_mcp_min.py https://api.example.com/openapi.json
```

### 🛠️ Advanced Options

```bash
# Override API base URL (useful when docs and API are hosted separately)
python openapi_mcp_min.py http://localhost:8080/api-docs --api-base-url https://api.production.com

# Set public MCP server URL (for multi-host deployments)
python openapi_mcp_min.py http://localhost:8080/api-docs --public-url https://mcp.example.com

# Add context path prefix to all routes
python openapi_mcp_min.py http://localhost:8080/api-docs --context-path /mcp

# Start in degraded mode (even if API is unreachable)
python openapi_mcp_min.py http://unreachable-api.com/docs --ignore-errors

# Enable verbose debug logging
DEBUG=1 python openapi_mcp_min.py http://localhost:8080/api-docs

# Combine all options
DEBUG=1 PORT=9000 python openapi_mcp_min.py http://localhost:8080/api-docs \
  --api-base-url https://api.example.com \
  --public-url https://mcp.example.com \
  --context-path /api/mcp \
  --ignore-errors
```

## 📋 What You'll See

When starting successfully, you'll get detailed information about discovered tools:

```
📋 API Configuration:
   Base URL: https://petstore.swagger.io
   Total tools discovered: 20

🔧 Discovered tools/endpoints:
   • addPet                    POST   https://petstore.swagger.io/pet
     ↳ Add a new pet to the store
   • getPetById                GET    https://petstore.swagger.io/pet/{petId}
     ↳ Find pet by ID
   [... and more]

✓ MCP server ready with 20 tools available
✓ All API calls will be proxied to: https://petstore.swagger.io
```

With custom base URL, you'll see:

```
📋 API Configuration:
   Base URL: https://api.production.com
   ↳ Custom base URL provided via --api-base-url
   Total tools discovered: 20

✓ All API calls will be proxied to: https://api.production.com
```

## 🔧 How It Works

1. 📖 **Reads OpenAPI spec** from the provided URL
2. 🔄 **Converts each endpoint** into an MCP tool with proper schemas
3. 🌐 **Starts FastAPI server** that implements MCP protocol
4. 🎯 **Proxies tool calls** to the original API endpoints
5. 📤 **Returns responses** in MCP-compatible format

## 🌐 MCP Endpoints

Once running, the server provides these endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `POST /` | POST | 🎯 Main MCP JSON-RPC endpoint |
| `GET /` | GET | ℹ️ Server info and status (also SSE stream with `Accept: text/event-stream`) |
| `GET /health` | GET | ❤️ Health check |
| `GET /tools` | GET | 🔧 List all available tools |
| `GET /tools/list` | GET/POST | 📋 MCP tools list endpoint |
| `GET /resources/list` | GET | 📦 MCP resources (empty) |
| `GET /prompts/list` | GET | 💬 MCP prompts (empty) |
| `POST /tools/{tool_name}` | POST | ⚙️ Direct tool execution |

**Note:** All endpoints respect the `--context-path` prefix if configured.

## 🐛 Error Handling

### 🚫 API Unreachable
```bash
✗ Cannot reach OpenAPI URL: Unable to connect to http://api.example.com
💡 Use --ignore-errors flag to start server anyway for testing
```

### ⚠️ Degraded Mode
```bash
⚠️  Starting server in degraded mode (no tools available)
```

### ✅ Success
```bash
✓ OpenAPI URL is reachable
✓ MCP server ready with 15 tools available
```

## 🤖 Using with Claude Code

1. 🚀 Start the MCP server
2. 📝 Add to your MCP client configuration
3. 🎯 Use the discovered tools in your conversations!

## 🔐 Authentication

Set environment variables for API authentication:

```bash
# Bearer token authentication (preferred)
export API_BEARER="your-api-token"
python openapi_mcp_min.py https://api.example.com/openapi.json

# Alternative bearer token variable
export BEARER_TOKEN="your-api-token"
python openapi_mcp_min.py https://api.example.com/openapi.json

# API Key authentication (auto-detects header/query placement from OpenAPI spec)
export API_KEY="your-api-key"
python openapi_mcp_min.py https://api.example.com/openapi.json

# Basic authentication
export API_USERNAME="your-username"
export API_PASSWORD="your-password"
python openapi_mcp_min.py https://api.example.com/openapi.json

# Skip TLS verification (for development)
export SKIP_TLS_VERIFY=true
python openapi_mcp_min.py https://self-signed-api.com/docs
```

## 📝 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `8765` |
| `DEBUG` | Enable verbose debug logging (`1`, `true`, `yes`) | `false` |
| `API_BEARER` | Bearer token for API auth | None |
| `BEARER_TOKEN` | Alternative bearer token variable | None |
| `API_KEY` | API key for authentication | None |
| `API_USERNAME` | Username for basic auth | None |
| `API_PASSWORD` | Password for basic auth | None |
| `SKIP_TLS_VERIFY` | Skip TLS verification (`1`, `true`, `TRUE`) | `false` |
| `API_BASE_URL` | Fallback API base URL | `http://localhost:8080` |

## 🎯 Command Line Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `<OPENAPI_URL>` | OpenAPI spec URL (required) | `http://localhost:8080/api-docs` |
| `--api-base-url` | Override API base URL | `--api-base-url https://api.example.com` |
| `--public-url` | Public MCP server URL | `--public-url https://mcp.example.com` |
| `--context-path` | Context path prefix for all routes | `--context-path /mcp` |
| `--ignore-errors` | Start in degraded mode if API unreachable | `--ignore-errors` |

## 🎨 Examples

### 🐾 Petstore API
```bash
python openapi_mcp_min.py https://petstore.swagger.io/v2/swagger.json
```

### 🌤️ Weather API
```bash
export API_BEARER="your-weather-api-key"
python openapi_mcp_min.py https://api.openweathermap.org/data/3.0/openapi.json
```

### 🔧 Local Development API
```bash
python openapi_mcp_min.py http://localhost:3000/api-docs --ignore-errors
```

### 🏢 Production API with Separate Documentation
```bash
# Get OpenAPI docs from staging but proxy calls to production
python openapi_mcp_min.py http://staging.api.com/docs --api-base-url https://api.production.com
```

### 🛣️ Context Path Deployment
```bash
# Deploy under /api/mcp path (useful for reverse proxies)
python openapi_mcp_min.py http://localhost:8080/api-docs --context-path /api/mcp
# Access at: http://localhost:8765/api/mcp/
```

### 🔍 Debug Mode
```bash
# Enable verbose logging for troubleshooting
DEBUG=1 python openapi_mcp_min.py http://localhost:8080/api-docs
```

## 🆘 Troubleshooting

### 🔍 Common Issues

**Server won't start:**
- ✅ Check if the OpenAPI URL is accessible
- ✅ Try with `--ignore-errors` flag
- ✅ Verify the URL returns valid JSON/YAML

**No tools discovered:**
- ✅ Ensure the OpenAPI spec has `paths` defined
- ✅ Check if the spec is valid OpenAPI 3.x format

**Connection errors:**
- ✅ Check firewall settings
- ✅ Verify the target API is running
- ✅ Try with `SKIP_TLS_VERIFY=true` for self-signed certs

## 📜 License

This is a minimal, educational implementation. Use it as a starting point for your own MCP servers!

---

Made with ❤️ for the MCP ecosystem