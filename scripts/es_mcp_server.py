import sys
import json
import ssl
import base64
import urllib.request
import urllib.error

ES_HOST = "https://localhost:9200"
ES_USER = "elastic"
ES_PASS = "admin1"

def get_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def es_request(endpoint, method="GET", body=None):
    url = f"{ES_HOST}{endpoint}" if endpoint.startswith("/") else f"{ES_HOST}/{endpoint}"
    data = None
    headers = {"Content-Type": "application/json"}
    auth_str = f"{ES_USER}:{ES_PASS}"
    auth_b64 = base64.b64encode(auth_str.encode("utf-8")).decode("ascii")
    headers["Authorization"] = f"Basic {auth_b64}"

    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode("utf-8")
        else:
            data = str(body).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    ctx = get_ssl_context()
    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            content = resp.read().decode("utf-8")
            try:
                return json.loads(content)
            except Exception:
                return content
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        return {"error": e.code, "reason": e.reason, "details": err_body}
    except Exception as e:
        return {"error": "request_failed", "details": str(e)}

TOOLS = [
    {
        "name": "es_cluster_health",
        "description": "Get Elasticsearch cluster health and shard status.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "es_list_indices",
        "description": "List all indices in Elasticsearch with doc count and health status.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "es_search_logs",
        "description": "Search log events or documents in an index using Elasticsearch queries.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "index": {
                    "type": "string",
                    "description": "Index or index pattern to search (e.g., logs-*, winlogbeat-*)."
                },
                "query": {
                    "type": "string",
                    "description": "Lucene query string (e.g., 'level:ERROR', 'status:500', or '*').",
                    "default": "*"
                },
                "size": {
                    "type": "integer",
                    "description": "Number of log records to retrieve (default: 10).",
                    "default": 10
                }
            },
            "required": ["index"]
        }
    },
    {
        "name": "es_raw_api",
        "description": "Execute any Elasticsearch REST API call (GET, POST, PUT, DELETE).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "endpoint": {
                    "type": "string",
                    "description": "API endpoint, e.g. /_cat/nodes, /_nodes/stats, /my-index/_mapping."
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "DELETE"],
                    "default": "GET"
                },
                "body": {
                    "type": "object",
                    "description": "JSON request payload body if needed."
                }
            },
            "required": ["endpoint"]
        }
    }
]

def handle_request(req):
    req_id = req.get("id")
    method = req.get("method")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "elasticsearch-investigator",
                    "version": "1.0.0"
                }
            }
        }
    elif method == "notifications/initialized":
        return None
    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": TOOLS
            }
        }
    elif method == "tools/call":
        params = req.get("params", {})
        tool_name = params.get("name")
        args = params.get("arguments", {})

        result_content = ""
        try:
            if tool_name == "es_cluster_health":
                res = es_request("/_cluster/health")
                result_content = json.dumps(res, indent=2)
            elif tool_name == "es_list_indices":
                res = es_request("/_cat/indices?v&format=json")
                result_content = json.dumps(res, indent=2)
            elif tool_name == "es_search_logs":
                idx = args.get("index", "*")
                query = args.get("query", "*")
                size = args.get("size", 10)
                body = {
                    "size": size,
                    "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "boolean"}}],
                    "query": {
                        "query_string": {
                            "query": query
                        }
                    }
                }
                res = es_request(f"/{idx}/_search", method="POST", body=body)
                result_content = json.dumps(res, indent=2)
            elif tool_name == "es_raw_api":
                endpoint = args.get("endpoint")
                http_method = args.get("method", "GET")
                body = args.get("body")
                res = es_request(endpoint, method=http_method, body=body)
                result_content = json.dumps(res, indent=2) if isinstance(res, (dict, list)) else str(res)
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method {tool_name} not found"
                    }
                }
        except Exception as e:
            result_content = json.dumps({"error": str(e)})

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": result_content
                    }
                ]
            }
        }
    elif method == "ping":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {}
        }
    else:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Unknown method: {method}"
            }
        }

def main():
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            res = handle_request(req)
            if res is not None:
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
        except Exception as err:
            err_res = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": f"Parse error: {str(err)}"
                }
            }
            sys.stdout.write(json.dumps(err_res) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()

