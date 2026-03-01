"""
Flask auth proxy for DNS MCP Server.
Validates bearer token and forwards requests to FastMCP server.
"""
from flask import Flask, request, Response
import os
import requests

app = Flask(__name__)
BEARER_TOKEN = os.getenv("MCP_BEARER_TOKEN", "")
MCP_BACKEND = os.getenv("MCP_BACKEND_URL", "http://localhost:8083")


@app.before_request
def check_auth():
    # Allow OPTIONS requests (CORS preflight) without auth
    if request.method == 'OPTIONS':
        return '', 200

    auth = request.headers.get("authorization", "")
    if auth != f"Bearer {BEARER_TOKEN}":
        return Response('{"error": "Unauthorized"}', status=401, mimetype='application/json')


@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy(path):
    # Forward to FastMCP DNS server (configurable for Docker networking)
    url = f"{MCP_BACKEND}/{path}"

    # Stream the response instead of buffering
    resp = requests.request(
        method=request.method,
        url=url,
        headers={k: v for k, v in request.headers if k.lower() != 'host'},
        data=request.get_data(),
        stream=True,
        allow_redirects=False
    )

    # Stream response back with CORS headers
    def generate():
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                yield chunk

    response = Response(
        generate(),
        status=resp.status_code,
        headers=dict(resp.headers)
    )

    # Add CORS headers
    response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
    response.headers['Access-Control-Allow-Credentials'] = 'true'

    return response


if __name__ == "__main__":
    print(f"Auth proxy starting on port 8082")
    print(f"Forwarding to FastMCP on port 8083")
    print(f"Token: {BEARER_TOKEN[:20]}...")
    app.run(host="127.0.0.1", port=8082)
