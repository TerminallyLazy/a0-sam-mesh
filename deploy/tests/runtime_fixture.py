"""Disposable issuer and destination witness. Never a production issuer."""

import base64
import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(os.environ["FIXTURE_ROOT"])
ROOT.mkdir(parents=True, exist_ok=True)
os.chmod(ROOT, 0o700)
ISSUER = os.environ.get("FIXTURE_ISSUER", "http://127.0.0.1:18081")
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def enc(v):
    return base64.urlsafe_b64encode(v).rstrip(b"=")


def num(v):
    return enc(v.to_bytes((v.bit_length() + 7) // 8, "big")).decode()


public = key.public_key().public_numbers()
jwks = {
    "keys": [
        {
            "kty": "RSA",
            "kid": "certification",
            "use": "sig",
            "alg": "RS256",
            "n": num(public.n),
            "e": num(public.e),
        }
    ]
}


def issue(name, expires, audience="sovereign-cert", subject="a0-cert"):
    body = enc(
        json.dumps(
            {
                "iss": ISSUER,
                "aud": audience,
                "sub": subject,
                "exp": expires,
                "iat": int(time.time()),
            }
        ).encode()
    )
    header = enc(b'{"alg":"RS256","kid":"certification"}')
    data = header + b"." + body
    token = data + b"." + enc(key.sign(data, padding.PKCS1v15(), hashes.SHA256()))
    path = ROOT / name
    path.write_bytes(token)
    path.chmod(0o600)


for name, exp, aud in [
    ("valid.jwt", time.time() + 7200, "sovereign-cert"),
    ("expired.jwt", time.time() - 10, "sovereign-cert"),
    ("short.jwt", time.time() + 60, "sovereign-cert"),
    ("wrong.jwt", time.time() + 7200, "wrong"),
]:
    issue(name, exp, aud)

issue("wrong-subject.jwt", time.time() + 7200, subject="other-workload")
invalid = (ROOT / "valid.jwt").read_bytes().split(b".")
invalid[2] = (b"A" if invalid[2][:1] != b"A" else b"B") + invalid[2][1:]
(ROOT / "invalid-signature.jwt").write_bytes(b".".join(invalid))
(ROOT / "invalid-signature.jwt").chmod(0o600)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/.well-known/openid-configuration":
            data = {
                "issuer": ISSUER,
                "jwks_uri": ISSUER + "/keys",
                "id_token_signing_alg_values_supported": ["RS256"],
                "response_types_supported": ["id_token"],
                "subject_types_supported": ["public"],
            }
        elif self.path == "/v1/models":
            data = {
                "object": "list",
                "data": [
                    {
                        "id": "sovereign-fixture",
                        "object": "model",
                        "created": 0,
                        "owned_by": "disposable-certification",
                    }
                ],
            }
        elif self.path == "/keys":
            data = jwks
        elif self.path == "/issue-short":
            issue("short.jwt", time.time() + 36)
            data = {"issued": True}
        else:
            data = {"witness": "allowed-destination"}
            with (ROOT / "http-witness.log").open("a") as f:
                f.write(self.path + "\n")
        payload = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length))
        if self.path == "/v1/chat/completions":
            content = json.dumps(
                {"tool_name": "response", "tool_args": {"text": "native-sovereign-guest-ok"}}
            )
            (ROOT / "model-witness.log").open("a").write("native-model-request\n")
            response = {
                "id": "sovereign-fixture",
                "object": "chat.completion",
                "created": 0,
                "model": "sovereign-fixture",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
            if request.get("stream"):
                chunk = {
                    "id": "sovereign-fixture",
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": "sovereign-fixture",
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"role": "assistant", "content": content},
                            "finish_reason": None,
                        }
                    ],
                }
                payload = ("data: " + json.dumps(chunk) + "\n\ndata: [DONE]\n\n").encode()
                kind = "text/event-stream"
            else:
                payload = json.dumps(response).encode()
                kind = "application/json"
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        method = request.get("method")
        if method == "initialize":
            result = {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "sovereign-network-witness", "version": "1"},
            }
        elif method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "probe",
                        "description": "Return the disposable route witness",
                        "inputSchema": {"type": "object", "properties": {}},
                        "annotations": {"readOnlyHint": True},
                    }
                ]
            }
        else:
            result = {"content": [{"type": "text", "text": "named-mesh-witness"}]}
        if "id" not in request:
            self.send_response(202)
            self.end_headers()
            return
        payload = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def receive(udp, log_name):
    while True:
        data, address = udp.recvfrom(65535)
        with (ROOT / log_name).open("ab") as f:
            f.write(data + b"\n")
        udp.sendto(data, address)


for port, log_name in [(18082, "udp-witness.log"), (53, "dns-witness.log")]:
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", port))
    threading.Thread(target=receive, args=(udp, log_name), daemon=True).start()
ThreadingHTTPServer(("0.0.0.0", 18081), Handler).serve_forever()
