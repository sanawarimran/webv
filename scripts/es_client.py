import sys
import json
import ssl
import base64
import urllib.request
import urllib.error
import argparse

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
    headers = {
        "Content-Type": "application/json"
    }
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

def main():
    parser = argparse.ArgumentParser(description="Elasticsearch Investigation & Query CLI")
    subparsers = parser.add_subparsers(dest="command")

    # health
    subparsers.add_parser("health", help="Check cluster health")

    # indices
    subparsers.add_parser("indices", help="List all indices")

    # search
    search_parser = subparsers.add_parser("search", help="Search documents/logs in an index")
    search_parser.add_argument("--index", required=True, help="Index pattern, e.g. logs-* or filebeat-*")
    search_parser.add_argument("--query", default="*", help="Query string or Lucene filter")
    search_parser.add_argument("--size", type=int, default=10, help="Number of records to fetch")

    # raw query
    raw_parser = subparsers.add_parser("raw", help="Raw API call")
    raw_parser.add_argument("--endpoint", required=True, help="API endpoint, e.g. /_cat/nodes")
    raw_parser.add_argument("--method", default="GET", help="HTTP Method")
    raw_parser.add_argument("--body", default=None, help="JSON body")

    # index doc
    index_parser = subparsers.add_parser("index_doc", help="Index a document")
    index_parser.add_argument("--index", required=True, help="Target index")
    index_parser.add_argument("--doc", required=True, help="JSON document string")

    args = parser.parse_args()

    if args.command == "health":
        res = es_request("/_cluster/health")
        print(json.dumps(res, indent=2))
    elif args.command == "indices":
        res = es_request("/_cat/indices?v&format=json")
        print(json.dumps(res, indent=2))
    elif args.command == "search":
        q_body = {
            "size": args.size,
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "boolean"}}],
            "query": {
                "query_string": {
                    "query": args.query
                }
            }
        }
        res = es_request(f"/{args.index}/_search", method="POST", body=q_body)
        print(json.dumps(res, indent=2))
    elif args.command == "index_doc":
        try:
            doc_data = json.loads(args.doc)
        except Exception as e:
            print(json.dumps({"error": "invalid_json", "details": str(e)}))
            return
        res = es_request(f"/{args.index}/_doc", method="POST", body=doc_data)
        print(json.dumps(res, indent=2))
    elif args.command == "raw":
        body = None
        if args.body:
            try:
                body = json.loads(args.body)
            except Exception:
                body = args.body
        res = es_request(args.endpoint, method=args.method, body=body)
        print(json.dumps(res, indent=2) if isinstance(res, (dict, list)) else res)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

