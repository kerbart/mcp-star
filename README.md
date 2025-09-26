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
# Start in degraded mode (even if API is unreachable)
python openapi_mcp_min.py http://unreachable-api.com/docs --ignore-errors

# With custom port and error ignoring
PORT=9000 python openapi_mcp_min.py http://localhost:3000/api-docs --ignore-errors
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
| `GET /` | GET | ℹ️ Server info and status |
| `GET /health` | GET | ❤️ Health check |
| `GET /tools` | GET | 🔧 List all available tools |

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
# Bearer token authentication
export API_BEARER="your-api-token"
python openapi_mcp_min.py https://api.example.com/openapi.json

# Skip TLS verification (for development)
export SKIP_TLS_VERIFY=true
python openapi_mcp_min.py https://self-signed-api.com/docs
```

## 📝 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `8765` |
| `API_BEARER` | Bearer token for API auth | None |
| `SKIP_TLS_VERIFY` | Skip TLS verification | `false` |

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