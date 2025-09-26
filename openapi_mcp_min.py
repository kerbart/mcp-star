#!/usr/bin/env python3
"""
openapi_mcp_min.py — Serveur MCP minimal en 1 fichier
Usage: python openapi_mcp_min.py <OPENAPI_URL> [--api-base-url API_BASE_URL] [--ignore-errors]
"""
from __future__ import annotations
import sys, os, json, re, asyncio
from typing import Any, Dict, List, Optional
from contextlib import asynccontextmanager

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Path, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware

APP_NAME = "openapi-mcp-min"
APP_VER = "0.1.0"
MCP_PROTOCOL_VERSION = "2025-06-18"

# MCP Server capabilities and info
SERVER_INFO = {
    "name": APP_NAME,
    "version": APP_VER
}

SERVER_CAPABILITIES = {
    "tools": {
        "listChanged": False
    }
}

# ------------------------------
# Chargement OpenAPI (JSON/YAML)
# ------------------------------
async def fetch_text(url: str) -> str:
    verify = os.getenv("SKIP_TLS_VERIFY") not in ("1", "true", "TRUE")
    try:
        async with httpx.AsyncClient(verify=verify, timeout=20) as client:
            r = await client.get(url)
            r.raise_for_status()
            return r.text
    except httpx.ConnectError as e:
        print(f"Connection error while fetching {url}: {e}")
        raise RuntimeError(f"Unable to connect to {url}. Please check the URL and network connectivity.")
    except httpx.TimeoutException as e:
        print(f"Timeout error while fetching {url}: {e}")
        raise RuntimeError(f"Timeout while connecting to {url}. The server may be slow or unavailable.")
    except httpx.HTTPStatusError as e:
        print(f"HTTP error while fetching {url}: {e}")
        raise RuntimeError(f"HTTP error {e.response.status_code} while fetching {url}: {e.response.text}")
    except Exception as e:
        print(f"Unexpected error while fetching {url}: {e}")
        raise RuntimeError(f"Failed to fetch OpenAPI documentation from {url}: {str(e)}")

def parse_openapi(text: str) -> Dict[str, Any]:
    try:
        data = json.loads(text)
        return data
    except json.JSONDecodeError:
        try:
            return yaml.safe_load(text)
        except yaml.YAMLError as e:
            print(f"Failed to parse OpenAPI document as JSON or YAML: {e}")
            raise RuntimeError(f"Invalid OpenAPI document format. Expected JSON or YAML but got: {text[:200]}...")

# ------------------------------
# Mapping opérations → tools
# ------------------------------
class Tool:
    def __init__(self, name: str, method: str, path: str, summary: str | None, params: Dict[str, Any], has_body: bool):
        self.name = name
        self.method = method.upper()
        self.path = path
        self.summary = summary or ""
        self.params = params  # {"path": [..], "query": [..]}
        self.has_body = has_body

    def to_public(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.summary,
            "inputSchema": {
                "type": "object",
                "properties": self._schema_props(),
                "required": [p["name"] for p in self.params.get("path", [])],
            },
            "metadata": {"method": self.method, "path": self.path},
        }

    def _schema_props(self) -> Dict[str, Any]:
        props: Dict[str, Any] = {}
        for p in self.params.get("path", []):
            props[p["name"]] = {"type": p.get("schema", {}).get("type", "string")}
        for p in self.params.get("query", []):
            props[p["name"]] = {"type": p.get("schema", {}).get("type", "string")}
        if self.has_body:
            props["body"] = {"type": "object"}
        return props

# Utilitaires
_slugify = re.compile(r"[^a-z0-9_]+")

def tool_name(method: str, path: str, operation: Dict[str, Any]) -> str:
    if opid := operation.get("operationId"):
        return opid
    base = f"{method.lower()}_" + _slugify.sub("_", path.strip("/").replace("{", "").replace("}", "").lower())
    return base or f"{method.lower()}_root"

# Extraction params (path/query) + body

def collect_params(operation: Dict[str, Any], path_item_params: List[Dict[str, Any]]) -> tuple[Dict[str, Any], bool]:
    params = {"path": [], "query": []}
    all_params = (operation.get("parameters") or []) + (path_item_params or [])
    # privilégier les params de l'opération en cas de doublon
    seen = set()
    for p in all_params:
        key = (p.get("in"), p.get("name"))
        if key in seen: continue
        seen.add(key)
        if p.get("in") == "path":
            params["path"].append(p)
        elif p.get("in") == "query":
            params["query"].append(p)
    has_body = False
    if rb := operation.get("requestBody"):
        content = rb.get("content", {})
        if any(ct.startswith("application/json") for ct in content.keys()):
            has_body = True
    return params, has_body

# ------------------------------
# Construction du catalogue
# ------------------------------
class Catalogue:
    def __init__(self, base_url: str, tools: Dict[str, Tool]):
        self.base_url = base_url.rstrip("/")
        self.tools = tools

async def build_catalogue(openapi_url: str, custom_base_url: str = None) -> Catalogue:
    try:
        text = await fetch_text(openapi_url)
        spec = parse_openapi(text)
    except Exception as e:
        print(f"Failed to load OpenAPI specification from {openapi_url}: {e}")
        raise RuntimeError(f"Cannot initialize MCP server: {str(e)}")

    # Extract base URL - priority: custom_base_url > OpenAPI spec > derive from openapi_url
    base_url = None

    # Priority 1: Use custom base URL if provided
    if custom_base_url:
        base_url = custom_base_url.rstrip("/")
    else:
        # Priority 2: Try to get from OpenAPI spec servers
        if "servers" in spec and spec["servers"]:
            server_url = spec["servers"][0].get("url", "")
            if server_url:
                # If server URL contains localhost, replace with actual host from openapi_url
                if "localhost" in server_url or "127.0.0.1" in server_url:
                    from urllib.parse import urlparse
                    parsed_openapi = urlparse(openapi_url)
                    # Replace localhost with actual host but keep the port from the server URL
                    if "localhost:" in server_url:
                        port = server_url.split("localhost:")[1].split("/")[0]
                        base_url = f"{parsed_openapi.scheme}://{parsed_openapi.netloc.split(':')[0]}:{port}"
                    elif "127.0.0.1:" in server_url:
                        port = server_url.split("127.0.0.1:")[1].split("/")[0]
                        base_url = f"{parsed_openapi.scheme}://{parsed_openapi.netloc.split(':')[0]}:{port}"
                    else:
                        # No port specified, use the openapi_url host and port
                        base_url = f"{parsed_openapi.scheme}://{parsed_openapi.netloc}"
                else:
                    base_url = server_url.rstrip("/")

        # Priority 3: If no servers in spec, derive from openapi_url
        if not base_url:
            from urllib.parse import urlparse
            parsed_openapi = urlparse(openapi_url)
            base_url = f"{parsed_openapi.scheme}://{parsed_openapi.netloc}"

        # Fallback to environment variable or default
        if not base_url:
            base_url = os.getenv("API_BASE_URL", "http://localhost:8080")

    base_url = base_url.rstrip("/")

    # Handle relative base URLs by making them absolute based on openapi_url
    if base_url.startswith("/"):
        from urllib.parse import urlparse
        parsed_openapi = urlparse(openapi_url)
        base_url = f"{parsed_openapi.scheme}://{parsed_openapi.netloc}{base_url}"

    tools: Dict[str, Tool] = {}
    paths: Dict[str, Any] = spec.get("paths", {})
    for path, path_item in paths.items():
        path_params = path_item.get("parameters", []) if isinstance(path_item, dict) else []
        for method in ["get", "post", "put", "delete", "patch"]:
            if not isinstance(path_item, dict) or method not in path_item:
                continue
            op = path_item[method]
            name = tool_name(method, path, op)
            params, has_body = collect_params(op, path_params)
            summary = op.get("summary") or op.get("description")
            tools[name] = Tool(name, method, path, summary, params, has_body)

    catalogue = Catalogue(base_url, tools)

    # Print detailed information about discovered tools and API configuration
    print(f"\n📋 API Configuration:", flush=True)
    print(f"   Base URL: {base_url}", flush=True)
    if custom_base_url:
        print(f"   ↳ Custom base URL provided via --api-base-url", flush=True)
    print(f"   Total tools discovered: {len(tools)}", flush=True)

    if tools:
        print(f"\n🔧 Discovered tools/endpoints:", flush=True)
        for name, tool in tools.items():
            endpoint_url = f"{base_url}{tool.path}"
            print(f"   • {name:<25} {tool.method:<6} {endpoint_url}", flush=True)
            if tool.summary:
                print(f"     ↳ {tool.summary}", flush=True)
    else:
        print(f"   ⚠️  No tools/endpoints found in OpenAPI specification", flush=True)

    print("", flush=True)  # Empty line for readability

    return catalogue

# ------------------------------
# Exécution d'un tool → proxy HTTP
# ------------------------------
async def call_backend(cat: Catalogue, tool: Tool, args: Dict[str, Any]) -> httpx.Response:
    # Construire l'URL avec path params
    def fill_path(template: str, params: Dict[str, Any]) -> str:
        def repl(m):
            key = m.group(1)
            if key not in params:
                raise HTTPException(422, f"Paramètre de chemin manquant: {key}")
            return str(params[key])
        return re.sub(r"\{([^{}]+)\}", repl, template)

    path_filled = fill_path(tool.path, args)

    # Query params = args keys qui ne sont pas path/body connus
    query = {}
    path_names = {p["name"] for p in tool.params.get("path", [])}
    body = None
    if tool.has_body:
        body = args.get("body", None)
    for p in tool.params.get("query", []):
        name = p["name"]
        if name in args and args[name] is not None:
            query[name] = args[name]

    headers = {}
    if bearer := os.getenv("API_BEARER"):
        headers["Authorization"] = f"Bearer {bearer}"

    verify = os.getenv("SKIP_TLS_VERIFY") not in ("1", "true", "TRUE")

    async with httpx.AsyncClient(base_url=cat.base_url, verify=verify, timeout=30) as client:
        url = path_filled
        method = tool.method
        full_url = f"{cat.base_url}{url}"
        print(f"Making {method} request to: {full_url}")
        print(f"Query params: {query}")
        print(f"Headers: {headers}")

        try:
            if method == "GET":
                response = await client.get(url, params=query, headers=headers)
            elif method in ("POST", "PUT", "PATCH"):
                response = await client.request(method, url, params=query, headers=headers, json=body)
            elif method == "DELETE":
                response = await client.delete(url, params=query, headers=headers)
            else:
                raise HTTPException(400, f"Méthode non supportée: {method}")

            print(f"Response status: {response.status_code}")
            return response

        except Exception as e:
            print(f"Error making request to {full_url}: {str(e)}")
            raise

# ------------------------------
# API FastAPI (MCP minimal)
# ------------------------------
STATE: Dict[str, Any] = {"catalogue": None}

def parse_args():
    """Parse command line arguments"""
    if len(sys.argv) < 2:
        raise RuntimeError("Missing required OpenAPI URL argument")

    openapi_url = sys.argv[1]
    custom_base_url = None
    ignore_errors = False

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--api-base-url" and i + 1 < len(sys.argv):
            custom_base_url = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--ignore-errors":
            ignore_errors = True
            i += 1
        else:
            # For backwards compatibility, treat unknown flags as ignore-errors
            if sys.argv[i] == "--ignore-errors":
                ignore_errors = True
            i += 1

    return openapi_url, custom_base_url, ignore_errors

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    openapi_url, custom_base_url, ignore_errors = parse_args()

    try:
        STATE["catalogue"] = await build_catalogue(openapi_url, custom_base_url)
        print(f"✓ MCP server ready with {len(STATE['catalogue'].tools)} tools available", flush=True)
        print(f"✓ All API calls will be proxied to: {STATE['catalogue'].base_url}", flush=True)
    except Exception as e:
        if ignore_errors:
            print("⚠️  Starting server in degraded mode (no tools available)", flush=True)
            # Create empty catalogue for testing
            STATE["catalogue"] = Catalogue("http://localhost", {})
        else:
            # This should not happen since we pre-validate, but just in case
            raise RuntimeError(f"Unexpected error during startup: {str(e)}")

    yield

    # Shutdown (if needed)
    print("Shutting down MCP server...")

app = FastAPI(title=APP_NAME, version=APP_VER, lifespan=lifespan)

# Add CORS middleware to allow cross-origin requests from MCP clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# JSON-RPC 2.0 handler
async def handle_jsonrpc_request(request_data: Dict[str, Any]) -> Dict[str, Any]:
    method = request_data.get("method")
    params = request_data.get("params", {})
    request_id = request_data.get("id")

    # Handle initialize method (required for MCP protocol)
    if method == "initialize":
        client_version = params.get("protocolVersion", "")
        if client_version != MCP_PROTOCOL_VERSION:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32602,
                    "message": f"Unsupported protocol version {client_version}. Supported: {MCP_PROTOCOL_VERSION}"
                }
            }

        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": SERVER_CAPABILITIES,
                "serverInfo": SERVER_INFO
            }
        }

    cat: Catalogue = STATE["catalogue"]
    if not cat:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32603, "message": "Server not initialized"}
        }

    if method == "tools/list":
        items = [t.to_public() for t in cat.tools.values()] if cat and cat.tools else []
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"tools": items}
        }
    elif method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments", {})

        print(f"Calling tool: {tool_name} with args: {args}")

        if tool_name not in cat.tools:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32600, "message": f"Tool not found: {tool_name}"}
            }

        try:
            print(f"Starting backend call for tool: {tool_name}")
            resp = await call_backend(cat, cat.tools[tool_name], args)
            print(f"Backend call completed for tool: {tool_name}")

            content_type = resp.headers.get("content-type", "")
            print(f"Response content-type: {content_type}")

            if "application/json" in content_type:
                json_data = resp.json()
                # MCP expects content array with text entries
                result = {
                    "content": [
                        {
                            "type": "text",
                            "text": __import__("json").dumps(json_data, indent=2)
                        }
                    ]
                }
            else:
                result = {
                    "content": [
                        {
                            "type": "text",
                            "text": resp.text
                        }
                    ]
                }

            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": result
            }
        except Exception as e:
            print(f"Error in tools/call for {tool_name}: {str(e)}")
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": str(e)}
            }
    elif method == "resources/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"resources": []}
        }
    elif method == "prompts/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"prompts": []}
        }
    else:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": "Method not found"}
        }

@app.get("/")
async def root():
    cat: Catalogue = STATE["catalogue"]
    return {
        "name": "OpenAPI MCP Bridge",
        "version": APP_VER,
        "description": "MCP server that proxies OpenAPI/REST API endpoints as tools",
        "protocol": "MCP over HTTP (JSON-RPC 2.0)",
        "base_url": cat.base_url if cat else None,
        "tools_count": len(cat.tools) if cat else 0,
        "endpoints": {
            "POST /": "MCP JSON-RPC 2.0 protocol endpoint (REQUIRED for MCP clients)",
            "GET /": "Server information and status",
            "GET /health": "Health check",
            "GET /tools": "List all available tools",
            "POST /tools/{tool_name}": "Execute a tool directly (non-MCP)",
            "GET /tools/list": "MCP-compatible tools list",
            "GET /resources/list": "MCP-compatible resources list (empty)",
            "GET /prompts/list": "MCP-compatible prompts list (empty)"
        },
        "notice": "MCP clients must use POST / for proper protocol communication"
    }

@app.options("/")
async def options_root():
    return {"message": "CORS preflight OK"}

@app.post("/")
async def jsonrpc_endpoint(request: Request):
    try:
        request_data = await request.json()

        # Handle single request
        if isinstance(request_data, dict):
            if "jsonrpc" not in request_data or request_data["jsonrpc"] != "2.0":
                return JSONResponse(
                    {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid JSON-RPC version"}, "id": request_data.get("id")},
                    status_code=400
                )

            response = await handle_jsonrpc_request(request_data)
            return JSONResponse(response)

        # Handle batch requests
        elif isinstance(request_data, list):
            responses = []
            for req in request_data:
                if not isinstance(req, dict) or req.get("jsonrpc") != "2.0":
                    responses.append({"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid JSON-RPC version"}, "id": req.get("id") if isinstance(req, dict) else None})
                else:
                    response = await handle_jsonrpc_request(req)
                    responses.append(response)
            return JSONResponse(responses)

        else:
            return JSONResponse(
                {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None},
                status_code=400
            )

    except json.JSONDecodeError:
        return JSONResponse(
            {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None},
            status_code=400
        )
    except Exception as e:
        return JSONResponse(
            {"jsonrpc": "2.0", "error": {"code": -32603, "message": f"Internal error: {str(e)}"}, "id": None},
            status_code=500
        )

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": __import__("time").time()}

@app.get("/tools")
async def tools_info():
    cat: Catalogue = STATE["catalogue"]
    return {
        "total_tools": len(cat.tools),
        "available_tools": list(cat.tools.keys()),
        "base_url": cat.base_url
    }

@app.get("/tools/list")
async def tools_list():
    cat: Catalogue = STATE["catalogue"]
    items = [t.to_public() for t in cat.tools.values()]
    return {"tools": items}

@app.post("/tools/list")
async def tools_list_post():
    cat: Catalogue = STATE["catalogue"]
    items = [t.to_public() for t in cat.tools.values()]
    return {"tools": items}

@app.get("/resources/list")
async def resources_list():
    return {"resources": []}

@app.get("/prompts/list")
async def prompts_list():
    return {"prompts": []}

@app.post("/tools/{tool_name}")
async def run_tool(tool_name: str = Path(...), payload: Dict[str, Any] | None = None):
    cat: Catalogue = STATE["catalogue"]
    if tool_name not in cat.tools:
        raise HTTPException(404, f"Tool introuvable: {tool_name}")
    args = (payload or {}).get("arguments", {})
    resp = await call_backend(cat, cat.tools[tool_name], args)

    content_type = resp.headers.get("content-type", "")
    if "application/json" in content_type:
        return JSONResponse(resp.json(), status_code=resp.status_code)
    else:
        # renvoyer texte brut si non-JSON
        return PlainTextResponse(resp.text, status_code=resp.status_code)

def main():
    # Validate arguments early before starting FastAPI
    try:
        openapi_url, custom_base_url, ignore_errors = parse_args()
    except RuntimeError as e:
        print("Usage: python openapi_mcp_min.py <OPENAPI_URL> [--api-base-url API_BASE_URL] [--ignore-errors]")
        print("Example: python openapi_mcp_min.py http://localhost:8080/api-docs")
        print("         python openapi_mcp_min.py http://localhost:8080/api-docs --api-base-url https://api.example.com")
        print("         python openapi_mcp_min.py http://localhost:8080/api-docs --ignore-errors")
        print(f"\nError: {e}")
        sys.exit(2)

    if not ignore_errors:
        print(f"Validating OpenAPI URL: {openapi_url}", flush=True)
        if custom_base_url:
            print(f"Custom API base URL: {custom_base_url}", flush=True)
        try:
            # Test the connection before starting the server
            import asyncio
            asyncio.run(fetch_text(openapi_url))
            print("✓ OpenAPI URL is reachable", flush=True)
        except Exception as e:
            print(f"✗ Cannot reach OpenAPI URL: {e}", flush=True)
            print("💡 Use --ignore-errors flag to start server anyway for testing", flush=True)
            sys.exit(1)

    import uvicorn
    port = int(os.getenv("PORT", "8765"))
    print(f"Starting MCP server on port {port}...", flush=True)
    try:
        # Suppress uvicorn access logs when there are startup errors
        log_config = uvicorn.config.LOGGING_CONFIG.copy()
        if not ignore_errors:
            log_config["loggers"]["uvicorn.access"]["level"] = "WARNING"

        uvicorn.run("openapi_mcp_min:app", host="0.0.0.0", port=port, reload=False, log_config=log_config)
    except Exception as e:
        print(f"Failed to start server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()