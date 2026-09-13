"""Actual HTTP/WebSocket witness for the fixed-destination UI stream bridge."""

import base64
import hashlib
import socketserver


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        header = b""
        while not header.endswith(b"\r\n\r\n"):
            chunk = self.rfile.read(1)
            if not chunk:
                return
            header += chunk
        if b"Upgrade: websocket" in header:
            key = next(
                line.split(b":", 1)[1].strip()
                for line in header.split(b"\r\n")
                if line.lower().startswith(b"sec-websocket-key:")
            )
            accept = base64.b64encode(
                hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
            )
            self.wfile.write(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
                + accept
                + b"\r\n\r\n"
            )
            self.wfile.flush()
            head = self.rfile.read(2)
            mask = self.rfile.read(4)
            data = self.rfile.read(head[1] & 127)
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(data))
            self.wfile.write(b"\x81" + bytes([len(payload)]) + payload)
        else:
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


Server(("127.0.0.1", 18090), Handler).serve_forever()
