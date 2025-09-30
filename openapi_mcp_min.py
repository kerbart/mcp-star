#!/usr/bin/env python3
"""
openapi_mcp_min.py — Serveur MCP minimal en 1 fichier
Usage: python openapi_mcp_min.py <OPENAPI_URL> [--api-base-url API_BASE_URL] [--context-path CONTEXT_PATH] [--ignore-errors]

Logging:
  Set DEBUG=1 environment variable to enable verbose debug logging
  Example: DEBUG=1 python openapi_mcp_min.py <OPENAPI_URL>

The server logs all:
  - Incoming HTTP requests (method, path, client info)
  - JSON-RPC method calls (initialize, tools/list, tools/call)
  - Backend API calls (with full request/response details in debug mode)
  - Protocol negotiation
  - Errors with full tracebacks (in debug mode)
"""
from __future__ import annotations
import sys, os, json, re, asyncio, logging, traceback
from typing import Any, Dict, List, Optional
from contextlib import asynccontextmanager
from datetime import datetime

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Path, Request
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware

APP_NAME = "openapi-mcp-min"
APP_VER = "0.1.0"
SUPPORTED_PROTOCOL_VERSIONS = ["2024-11-05", "2025-03-26", "2025-06-18"]
KEEP_ALIVE_SECONDS = 25

# Configure logging
log_level = logging.DEBUG if os.getenv("DEBUG", "").lower() in ("1", "true", "yes") else logging.INFO
logging.basicConfig(
    level=log_level,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

if log_level == logging.DEBUG:
    logger.info("🐛 Debug logging enabled (set DEBUG=0 to disable)")

# MCP Server capabilities and info - will be updated with OpenAPI info
SERVER_INFO = {
    "name": APP_NAME,
    "version": APP_VER
}

SERVER_CAPABILITIES = {
    "tools": {
        "listChanged": False
    },
    "auth": {
        "bearer": True,
        "apiKey": True
    }
}

# ------------------------------
# Chargement OpenAPI (JSON/YAML)
# ------------------------------
async def fetch_text(url: str) -> str:
    verify = os.getenv("SKIP_TLS_VERIFY") not in ("1", "true", "TRUE")
    print(f"Fetching OpenAPI document from: {url}")

    # First try with httpx (original approach)
    try:
        async with httpx.AsyncClient(
            verify=verify,
            timeout=30.0,
            http2=False,
            follow_redirects=True
        ) as client:
            print(f"Attempting httpx connection to {url}...")
            response = await client.get(url)
            print(f"Response status: {response.status_code}")
            response.raise_for_status()
            return response.text

    except httpx.ConnectError as e:
        print(f"httpx connection failed: {e}")
        print(f"Falling back to urllib approach...")

        # Fallback to urllib for local network compatibility
        try:
            import urllib.request
            import urllib.error
            import ssl
            import asyncio
            from urllib.parse import urlparse

            # Configure SSL context if needed
            if url.startswith('https://') and not verify:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            else:
                ssl_context = None

            def fetch_sync():
                headers = {
                    'User-Agent': 'openapi-mcp-min/0.1.0',
                    'Accept': 'application/json, application/yaml, text/yaml, */*'
                }

                req = urllib.request.Request(url, headers=headers)

                if ssl_context and url.startswith('https://'):
                    response = urllib.request.urlopen(req, context=ssl_context, timeout=30)
                else:
                    response = urllib.request.urlopen(req, timeout=30)

                content = response.read().decode('utf-8')
                print(f"urllib response status: {response.status}")
                return content

            # Run the synchronous urllib call in a thread pool
            loop = asyncio.get_event_loop()
            content = await loop.run_in_executor(None, fetch_sync)
            return content

        except Exception as urllib_error:
            print(f"urllib fallback also failed: {urllib_error}")
            raise RuntimeError(f"All connection methods failed. httpx error: {e}, urllib error: {urllib_error}")

    except httpx.TimeoutException as e:
        print(f"Timeout error while fetching {url}: {e}")
        raise RuntimeError(f"Timeout while connecting to {url}. The server may be slow or unavailable.")
    except httpx.HTTPStatusError as e:
        print(f"HTTP error while fetching {url}: {e}")
        raise RuntimeError(f"HTTP error {e.response.status_code} while fetching {url}: {e.response.text}")
    except Exception as e:
        print(f"Unexpected error while fetching {url}: {e}")
        print(f"Error type: {type(e).__name__}")
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
    def __init__(self, base_url: str, tools: Dict[str, Tool], api_info: Dict[str, Any] = None, public_url: str = None, custom_base_url: bool = False):
        self.base_url = base_url.rstrip("/")
        self.tools = tools
        self.api_info = api_info or {}
        self.public_url = public_url.rstrip("/") if public_url else None
        self.custom_base_url = custom_base_url  # Track if base_url was explicitly provided

async def build_catalogue(openapi_url: str, custom_base_url: str = None, public_url: str = None) -> Catalogue:
    try:
        text = await fetch_text(openapi_url)
        spec = parse_openapi(text)
    except Exception as e:
        print(f"Failed to load OpenAPI specification from {openapi_url}: {e}")
        raise RuntimeError(f"Cannot initialize MCP server: {str(e)}")

    # Extract base URL - priority: custom_base_url > OpenAPI spec > derive from openapi_url
    base_url = None

    # Only use custom_base_url if explicitly provided
    if custom_base_url:
        base_url = custom_base_url.rstrip("/")
        # Handle relative base URLs by making them absolute based on openapi_url
        if base_url.startswith("/"):
            from urllib.parse import urlparse
            parsed_openapi = urlparse(openapi_url)
            base_url = f"{parsed_openapi.scheme}://{parsed_openapi.netloc}{base_url}"
    else:
        # Try to get from OpenAPI spec servers
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

        # If no servers in spec, derive from openapi_url
        if not base_url:
            from urllib.parse import urlparse
            parsed_openapi = urlparse(openapi_url)
            base_url = f"{parsed_openapi.scheme}://{parsed_openapi.netloc}"

        # Fallback to environment variable or default
        if not base_url:
            base_url = os.getenv("API_BASE_URL", "http://localhost:8080")

    # Extract API information for MCP server info
    api_info = {
        "title": spec.get("info", {}).get("title", "OpenAPI"),
        "description": spec.get("info", {}).get("description", ""),
        "version": spec.get("info", {}).get("version", "1.0.0"),
        "contact": spec.get("info", {}).get("contact", {}),
        "license": spec.get("info", {}).get("license", {}),
        "servers": spec.get("servers", []),
        "externalDocs": spec.get("externalDocs", {}),
        "securitySchemes": spec.get("components", {}).get("securitySchemes", {}),
        "security": spec.get("security", [])
    }

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

    catalogue = Catalogue(base_url, tools, api_info, public_url, custom_base_url=bool(custom_base_url))

    # Print detailed information about discovered tools and API configuration
    print(f"\n📋 API Configuration:", flush=True)
    if custom_base_url:
        print(f"   Base URL: {base_url}", flush=True)
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
    logger.debug(f"🔧 call_backend: tool={tool.name}, method={tool.method}, path={tool.path}")
    logger.debug(f"   Args: {json.dumps(args, indent=2)}")

    # Construire l'URL avec path params
    def fill_path(template: str, params: Dict[str, Any]) -> str:
        def repl(m):
            key = m.group(1)
            if key not in params:
                logger.error(f"❌ Missing path parameter: {key}")
                raise HTTPException(422, f"Paramètre de chemin manquant: {key}")
            return str(params[key])
        return re.sub(r"\{([^{}]+)\}", repl, template)

    path_filled = fill_path(tool.path, args)
    logger.debug(f"   Path filled: {path_filled}")

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

    # Handle authentication based on OpenAPI security schemes
    if cat.api_info and cat.api_info.get("securitySchemes"):
        security_schemes = cat.api_info.get("securitySchemes", {})

        # Check for Bearer token authentication
        if bearer := os.getenv("API_BEARER") or os.getenv("BEARER_TOKEN"):
            headers["Authorization"] = f"Bearer {bearer}"

        # Check for API Key authentication
        elif api_key := os.getenv("API_KEY"):
            # Look for API key schemes in security definitions
            for scheme_name, scheme in security_schemes.items():
                if scheme.get("type") == "apiKey":
                    key_location = scheme.get("in", "header")
                    key_name = scheme.get("name", "X-API-Key")

                    if key_location == "header":
                        headers[key_name] = api_key
                    elif key_location == "query":
                        query[key_name] = api_key
                    break

        # Check for Basic authentication
        elif basic_user := os.getenv("API_USERNAME"):
            if basic_pass := os.getenv("API_PASSWORD"):
                import base64
                credentials = base64.b64encode(f"{basic_user}:{basic_pass}".encode()).decode()
                headers["Authorization"] = f"Basic {credentials}"

    # Fallback for backwards compatibility
    elif bearer := os.getenv("API_BEARER"):
        headers["Authorization"] = f"Bearer {bearer}"

    verify = os.getenv("SKIP_TLS_VERIFY") not in ("1", "true", "TRUE")

    # Configure transport for better local network compatibility
    transport = httpx.AsyncHTTPTransport(
        verify=verify,
        retries=2,
        http2=False
    )

    timeout = httpx.Timeout(30.0)

    async with httpx.AsyncClient(
        base_url=cat.base_url,
        transport=transport,
        timeout=timeout,
        follow_redirects=True
    ) as client:
        url = path_filled
        method = tool.method
        full_url = f"{cat.base_url}{url}"
        logger.info(f"🌐 {method} {full_url}")
        if query:
            logger.debug(f"   Query params: {json.dumps(query, indent=2)}")
        if headers:
            logger.debug(f"   Headers: {json.dumps(headers, indent=2)}")
        if body:
            logger.debug(f"   Body: {json.dumps(body, indent=2)[:500]}")

        try:
            if method == "GET":
                response = await client.get(url, params=query, headers=headers)
            elif method in ("POST", "PUT", "PATCH"):
                response = await client.request(method, url, params=query, headers=headers, json=body)
            elif method == "DELETE":
                response = await client.delete(url, params=query, headers=headers)
            else:
                logger.error(f"❌ Unsupported method: {method}")
                raise HTTPException(400, f"Méthode non supportée: {method}")

            logger.info(f"✅ Response: {response.status_code}")
            logger.debug(f"   Response headers: {dict(response.headers)}")
            return response

        except httpx.TimeoutException as e:
            logger.error(f"⏱️  Timeout making request to {full_url}: {str(e)}")
            raise
        except httpx.ConnectError as e:
            logger.error(f"🔌 Connection error to {full_url}: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"❌ Error making request to {full_url}: {str(e)}")
            logger.debug(f"   Traceback: {traceback.format_exc()}")
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

    # Validate that the first argument is not a flag
    if openapi_url.startswith("--"):
        raise RuntimeError(f"First argument must be OpenAPI URL, not a flag: {openapi_url}")

    custom_base_url = None
    public_url = None
    context_path = None
    ignore_errors = False

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--api-base-url" and i + 1 < len(sys.argv):
            custom_base_url = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--public-url" and i + 1 < len(sys.argv):
            public_url = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--context-path" and i + 1 < len(sys.argv):
            context_path = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--ignore-errors":
            ignore_errors = True
            i += 1
        else:
            # Unknown argument - raise error to help user identify the issue
            raise RuntimeError(f"Unknown argument: {sys.argv[i]}")

    return openapi_url, custom_base_url, public_url, context_path, ignore_errors

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("🚀 Starting MCP server...")
    openapi_url, custom_base_url, public_url, context_path, ignore_errors = parse_args()
    logger.info(f"   OpenAPI URL: {openapi_url}")
    if custom_base_url:
        logger.info(f"   Custom base URL: {custom_base_url}")
    if public_url:
        logger.info(f"   Public URL: {public_url}")
    if context_path:
        logger.info(f"   Context path: {context_path}")

    try:
        STATE["catalogue"] = await build_catalogue(openapi_url, custom_base_url, public_url)
        STATE["context_path"] = context_path.rstrip("/") if context_path else ""
        logger.info(f"✅ MCP server ready with {len(STATE['catalogue'].tools)} tools available")
        logger.info(f"   All API calls will be proxied to: {STATE['catalogue'].base_url}")
        if STATE['catalogue'].public_url:
            logger.info(f"   Public MCP server URL: {STATE['catalogue'].public_url}")
    except Exception as e:
        if ignore_errors:
            logger.warning("⚠️  Starting server in degraded mode (no tools available)")
            logger.error(f"   Error: {str(e)}")
            # Create empty catalogue for testing
            STATE["catalogue"] = Catalogue("http://localhost", {}, None, public_url)
            STATE["context_path"] = context_path.rstrip("/") if context_path else ""
        else:
            logger.error(f"❌ Failed to initialize: {str(e)}")
            logger.debug(f"   Traceback: {traceback.format_exc()}")
            # This should not happen since we pre-validate, but just in case
            raise RuntimeError(f"Unexpected error during startup: {str(e)}")

    yield

    # Shutdown (if needed)
    logger.info("🛑 Shutting down MCP server...")

app = FastAPI(title=APP_NAME, version=APP_VER, lifespan=lifespan)

def setup_routes(context_path: str = ""):
    """Setup routes with optional context path prefix"""
    prefix = context_path.rstrip("/") if context_path else ""

    @app.get(f"{prefix}/")
    async def root(request: Request):
        logger.info(f"🌐 GET {prefix}/ - User-Agent: {request.headers.get('user-agent', 'unknown')}")
        logger.debug(f"   Headers: {dict(request.headers)}")

        # Check if client wants SSE stream
        accept = request.headers.get("accept", "")
        if "text/event-stream" in accept:
            logger.info("📡 Starting SSE stream")
            async def event_generator():
                # Send initial ready event
                yield 'event: message\ndata: {"jsonrpc":"2.0","method":"server.ready","params":{"mcp_version":"1.0"}}\n\n'
                # Keep-alive loop to prevent proxy timeouts
                while True:
                    try:
                        await asyncio.sleep(KEEP_ALIVE_SECONDS)
                        # Send keep-alive comment
                        yield ": keep-alive\n\n"
                    except asyncio.CancelledError:
                        break

            headers = {
                "Cache-Control": "no-cache, no-transform",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            }
            return StreamingResponse(event_generator(), media_type="text/event-stream", headers=headers)

        cat: Catalogue = STATE["catalogue"]

        # Build comprehensive response with remote OpenAPI information
        response = {
            "name": "OpenAPI MCP Bridge",
            "protocol": "MCP over HTTP (JSON-RPC 2.0)",
            "mcp_version": "1.0",
            "endpoints": {
                "mcp_endpoint": f"{prefix}/",
                "tools_list": f"{prefix}/tools/list",
                "health_check": f"{prefix}/health",
                "tools_info": f"{prefix}/tools"
            }
        }

        # Add comprehensive OpenAPI information if available
        if cat and cat.api_info:
            api_details = {
                "title": cat.api_info.get("title"),
                "description": cat.api_info.get("description"),
                "version": cat.api_info.get("version")
            }

            # Only include base_url if it was explicitly provided via --api-base-url
            if cat.custom_base_url:
                api_details["base_url"] = cat.base_url

            # Add server information
            if cat.api_info.get("servers"):
                api_details["servers"] = cat.api_info.get("servers")

            # Add contact information
            if cat.api_info.get("contact"):
                api_details["contact"] = cat.api_info.get("contact")

            # Add license information
            if cat.api_info.get("license"):
                api_details["license"] = cat.api_info.get("license")

            # Add external documentation
            if cat.api_info.get("externalDocs"):
                api_details["external_docs"] = cat.api_info.get("externalDocs")

            # Add authentication schemes
            if cat.api_info.get("securitySchemes"):
                auth_schemes = []
                for scheme_name, scheme in cat.api_info.get("securitySchemes", {}).items():
                    auth_info = {
                        "name": scheme_name,
                        "type": scheme.get("type"),
                        "description": scheme.get("description", "")
                    }
                    if scheme.get("type") == "apiKey":
                        auth_info.update({
                            "in": scheme.get("in"),
                            "key_name": scheme.get("name")
                        })
                    elif scheme.get("type") == "http":
                        auth_info["scheme"] = scheme.get("scheme")
                    auth_schemes.append(auth_info)
                api_details["authentication_schemes"] = auth_schemes

            # Add security requirements
            if cat.api_info.get("security"):
                api_details["security_requirements"] = cat.api_info.get("security")

            # Remove None values
            api_details = {k: v for k, v in api_details.items() if v is not None and v != ""}

            response["openapi"] = api_details

        # Add tools summary
        if cat and cat.tools:
            response["tools_summary"] = {
                "total_tools": len(cat.tools),
                "available_tools": list(cat.tools.keys())
            }

        # Add public URL if configured
        if cat and cat.public_url:
            response["public_url"] = cat.public_url

        return response

    @app.options(f"{prefix}/{{path:path}}" if prefix else "/{path:path}")
    async def options_wildcard(path: str):
        """Wildcard OPTIONS handler for CORS preflight on all routes"""
        return JSONResponse(
            {"message": "CORS preflight OK"},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept, Mcp-Session-Id",
                "Access-Control-Expose-Headers": "Mcp-Session-Id",
            }
        )

    @app.post(f"{prefix}/")
    async def jsonrpc_endpoint(request: Request):
        logger.info(f"📬 POST {prefix}/ - User-Agent: {request.headers.get('user-agent', 'unknown')}")
        logger.debug(f"   Headers: {dict(request.headers)}")

        try:
            body_bytes = await request.body()
            logger.debug(f"   Request body (raw): {body_bytes.decode('utf-8', errors='replace')[:500]}")

            request_data = json.loads(body_bytes)
            logger.debug(f"   Request data (parsed): {json.dumps(request_data, indent=2)[:500]}")

            # Handle single request
            if isinstance(request_data, dict):
                if "jsonrpc" not in request_data or request_data["jsonrpc"] != "2.0":
                    logger.error(f"❌ Invalid JSON-RPC version: {request_data.get('jsonrpc')}")
                    return JSONResponse(
                        {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid JSON-RPC version"}, "id": request_data.get("id")},
                        status_code=400
                    )

                response = await handle_jsonrpc_request(request_data)
                logger.debug(f"   Response: {json.dumps(response, indent=2)[:500]}")
                return JSONResponse(response)

            # Handle batch requests
            elif isinstance(request_data, list):
                logger.info(f"📦 Batch request with {len(request_data)} items")
                responses = []
                for req in request_data:
                    if not isinstance(req, dict) or req.get("jsonrpc") != "2.0":
                        logger.error(f"❌ Invalid batch item: {req}")
                        responses.append({"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid JSON-RPC version"}, "id": req.get("id") if isinstance(req, dict) else None})
                    else:
                        response = await handle_jsonrpc_request(req)
                        responses.append(response)
                return JSONResponse(responses)

            else:
                logger.error(f"❌ Invalid request type: {type(request_data)}")
                return JSONResponse(
                    {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None},
                    status_code=400
                )

        except json.JSONDecodeError as e:
            logger.error(f"❌ JSON decode error: {str(e)}")
            return JSONResponse(
                {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None},
                status_code=400
            )
        except Exception as e:
            logger.error(f"❌ Internal error: {str(e)}")
            logger.debug(f"   Traceback: {traceback.format_exc()}")
            return JSONResponse(
                {"jsonrpc": "2.0", "error": {"code": -32603, "message": f"Internal error: {str(e)}"}, "id": None},
                status_code=500
            )

    @app.get(f"{prefix}/health")
    async def health_check():
        return {"status": "healthy", "timestamp": __import__("time").time()}

    @app.get(f"{prefix}/tools")
    async def tools_info():
        cat: Catalogue = STATE["catalogue"]
        result = {
            "total_tools": len(cat.tools),
            "available_tools": list(cat.tools.keys())
        }

        # Only include public_url if it was explicitly provided
        if cat.public_url:
            result["mcp_server_url"] = cat.public_url

        # Only include backend_api_url if it was explicitly provided via --api-base-url
        if cat.custom_base_url:
            result["backend_api_url"] = cat.base_url

        return result

    @app.get(f"{prefix}/tools/list")
    async def tools_list():
        cat: Catalogue = STATE["catalogue"]
        items = [t.to_public() for t in cat.tools.values()]
        return {"tools": items}

    @app.post(f"{prefix}/tools/list")
    async def tools_list_post():
        cat: Catalogue = STATE["catalogue"]
        items = [t.to_public() for t in cat.tools.values()]
        return {"tools": items}

    @app.get(f"{prefix}/resources/list")
    async def resources_list():
        return {"resources": []}

    @app.get(f"{prefix}/prompts/list")
    async def prompts_list():
        return {"prompts": []}

    @app.post(f"{prefix}/tools/{{tool_name}}")
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

# Setup CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    max_age=3600
)

# Setup logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = datetime.now()

    # Detect MCP client type from User-Agent
    user_agent = request.headers.get("user-agent", "unknown")
    client_type = "Unknown"
    if "mistral" in user_agent.lower():
        client_type = "🤖 Mistral Le Chat"
    elif "claude" in user_agent.lower():
        client_type = "🤖 Claude"
    elif "python" in user_agent.lower():
        client_type = "🐍 Python"
    elif "httpx" in user_agent.lower():
        client_type = "📡 HTTPX"

    # Log incoming request
    logger.info(f"⬇️  {request.method} {request.url.path} (from {client_type})")
    logger.debug(f"   Client: {request.client.host}:{request.client.port}")
    logger.debug(f"   User-Agent: {user_agent}")
    logger.debug(f"   Headers: {dict(request.headers)}")

    # Process request
    try:
        response = await call_next(request)
        duration_ms = (datetime.now() - start_time).total_seconds() * 1000
        logger.info(f"⬆️  {request.method} {request.url.path} → {response.status_code} ({duration_ms:.2f}ms)")
        return response
    except Exception as e:
        duration_ms = (datetime.now() - start_time).total_seconds() * 1000
        logger.error(f"💥 {request.method} {request.url.path} → ERROR ({duration_ms:.2f}ms): {str(e)}")
        raise

# JSON-RPC 2.0 handler
async def handle_jsonrpc_request(request_data: Dict[str, Any]) -> Dict[str, Any]:
    method = request_data.get("method")
    params = request_data.get("params", {})
    request_id = request_data.get("id")

    logger.info(f"📨 Received JSON-RPC request: method={method}, id={request_id}")
    logger.debug(f"   Params: {json.dumps(params, indent=2)}")

    # Handle initialize method (required for MCP protocol)
    # Also support mcp.discover as an alias
    if method == "initialize" or method == "mcp.discover":
        client_version = params.get("protocolVersion", "")

        # Tolerant protocol version negotiation (best-effort)
        def negotiate_protocol(client_ver: str) -> str:
            if not client_ver:
                return SUPPORTED_PROTOCOL_VERSIONS[-1]
            if client_ver in SUPPORTED_PROTOCOL_VERSIONS:
                return client_ver
            # Strategy: return most recent supported version
            return SUPPORTED_PROTOCOL_VERSIONS[-1]

        chosen_version = negotiate_protocol(client_version)
        logger.info(f"🤝 Protocol negotiation: client={client_version}, chosen={chosen_version}")

        cat: Catalogue = STATE["catalogue"]

        # Build enhanced server info from OpenAPI spec
        enhanced_server_info = SERVER_INFO.copy()
        if cat and cat.api_info:
            enhanced_server_info.update({
                "name": f"{cat.api_info.get('title', APP_NAME)} MCP Bridge",
                "version": f"{cat.api_info.get('version', '1.0.0')} (MCP {APP_VER})",
                "description": cat.api_info.get('description', 'MCP server that proxies OpenAPI/REST API endpoints as tools'),
                "contact": cat.api_info.get('contact'),
                "license": cat.api_info.get('license'),
                "externalDocs": cat.api_info.get('externalDocs')
            })

            # Add authentication information for MCP clients
            if cat.api_info.get('securitySchemes'):
                auth_schemes = []
                for scheme_name, scheme in cat.api_info.get('securitySchemes', {}).items():
                    auth_info = {
                        "name": scheme_name,
                        "type": scheme.get("type"),
                        "description": scheme.get("description", "")
                    }
                    if scheme.get("type") == "apiKey":
                        auth_info.update({
                            "in": scheme.get("in"),
                            "name": scheme.get("name")
                        })
                    elif scheme.get("type") == "http":
                        auth_info["scheme"] = scheme.get("scheme")
                    auth_schemes.append(auth_info)

                enhanced_server_info["authenticationSchemes"] = auth_schemes

            # Remove None values
            enhanced_server_info = {k: v for k, v in enhanced_server_info.items() if v is not None}

        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": chosen_version,
                "capabilities": SERVER_CAPABILITIES,
                "serverInfo": enhanced_server_info
            }
        }
        logger.info(f"✅ Sending initialize response with {len(cat.tools) if cat else 0} tools")
        return response

    cat: Catalogue = STATE["catalogue"]
    if not cat:
        logger.error("❌ Server not initialized")
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32603, "message": "Server not initialized"}
        }

    # Handle tools/list method (also support list_tools as an alias)
    if method == "tools/list" or method == "list_tools":
        items = [t.to_public() for t in cat.tools.values()] if cat and cat.tools else []
        logger.info(f"📋 Listing {len(items)} tools")
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"tools": items}
        }
    elif method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments", {})

        logger.info(f"🔧 Calling tool: {tool_name}")
        logger.debug(f"   Arguments: {json.dumps(args, indent=2)}")

        if tool_name not in cat.tools:
            logger.error(f"❌ Tool not found: {tool_name}")
            logger.info(f"   Available tools: {list(cat.tools.keys())}")
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32600, "message": f"Tool not found: {tool_name}"}
            }

        try:
            logger.info(f"🚀 Starting backend call for tool: {tool_name}")
            resp = await call_backend(cat, cat.tools[tool_name], args)
            logger.info(f"✅ Backend call completed: status={resp.status_code}")

            content_type = resp.headers.get("content-type", "")
            logger.debug(f"   Response content-type: {content_type}")

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

            logger.info(f"📤 Sending tool result for {tool_name}")
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": result
            }
        except Exception as e:
            logger.error(f"❌ Error in tools/call for {tool_name}: {str(e)}")
            logger.debug(f"   Traceback: {traceback.format_exc()}")
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": str(e)}
            }
    elif method == "resources/list":
        logger.info("📁 Listing resources (empty)")
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"resources": []}
        }
    elif method == "prompts/list":
        logger.info("💬 Listing prompts (empty)")
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"prompts": []}
        }
    else:
        logger.warning(f"⚠️  Unknown method: {method}")
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": "Method not found"}
        }

def main():
    # Validate arguments early before starting FastAPI
    try:
        openapi_url, custom_base_url, public_url, context_path, ignore_errors = parse_args()
    except RuntimeError as e:
        print("Usage: python openapi_mcp_min.py <OPENAPI_URL> [--api-base-url API_BASE_URL] [--public-url PUBLIC_URL] [--context-path CONTEXT_PATH] [--ignore-errors]")
        print("Example: python openapi_mcp_min.py http://localhost:8080/api-docs")
        print("         python openapi_mcp_min.py http://localhost:8080/api-docs --api-base-url https://api.example.com")
        print("         python openapi_mcp_min.py http://localhost:8080/api-docs --public-url https://mini-dvf.kerliane.eu/")
        print("         python openapi_mcp_min.py http://localhost:8080/api-docs --context-path /mcp")
        print("         python openapi_mcp_min.py http://localhost:8080/api-docs --ignore-errors")
        print(f"\nError: {e}")
        sys.exit(2)

    # Setup routes with context path
    setup_routes(context_path or "")

    if not ignore_errors:
        print(f"Validating OpenAPI URL: {openapi_url}", flush=True)
        if custom_base_url:
            print(f"Custom API base URL: {custom_base_url}", flush=True)
        if public_url:
            print(f"Public MCP server URL: {public_url}", flush=True)
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

    prefix = context_path.rstrip("/") if context_path else ""
    logger.info("=" * 70)
    logger.info(f"🚀 Starting MCP server on port {port}")
    logger.info(f"   Server URL: http://0.0.0.0:{port}{prefix}/")
    logger.info(f"   Health check: http://0.0.0.0:{port}{prefix}/health")
    logger.info(f"   Tools list: http://0.0.0.0:{port}{prefix}/tools")
    logger.info("=" * 70)

    try:
        # Suppress uvicorn access logs when there are startup errors
        log_config = uvicorn.config.LOGGING_CONFIG.copy()
        if not ignore_errors:
            log_config["loggers"]["uvicorn.access"]["level"] = "WARNING"

        # Reduce uvicorn noise
        log_config["loggers"]["uvicorn"]["level"] = "WARNING"
        log_config["loggers"]["uvicorn.error"]["level"] = "WARNING"

        uvicorn.run(app, host="0.0.0.0", port=port, reload=False, log_config=log_config)
    except Exception as e:
        logger.error(f"❌ Failed to start server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()