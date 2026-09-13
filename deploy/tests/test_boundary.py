"""The extra Sovereign restriction is tested independently of upstream routing."""

import importlib.util
import pathlib

import pytest

PATH = pathlib.Path(__file__).parents[1] / "scripts/boundary.py"
spec = importlib.util.spec_from_file_location("sovereign_boundary", PATH)
boundary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boundary)


@pytest.mark.parametrize(
    "wire",
    [
        b"GET /.well-known/masque/udp/allowed.test/53/ HTTP/1.1\r\nUpgrade: connect-udp\r\n\r\n",
        b"CONNECT 1.1.1.1:443 HTTP/1.1\r\n\r\n",
        b"CONNECT [::1]:80 HTTP/1.1\r\n\r\n",
        b"CONNECT allowed.test:53 HTTP/1.1\r\n\r\n",
        b"CONNECT denied.test:80 HTTP/1.1\r\n\r\n",
        b"CONNECT allowed.test:80 HTTP/1.1\r\nContent-Length: 2\r\n\r\n",
    ],
)
def test_no_udp_dns_literal_unapproved_or_body(wire):
    with pytest.raises(ValueError):
        boundary.connect_target(wire, {"allowed.test"})


def test_named_tcp_and_mesh_only():
    assert (
        boundary.connect_target(b"CONNECT allowed.test:443 HTTP/1.1\r\n\r\n", {"allowed.test"})
        == "allowed.test:443"
    )
    assert (
        boundary.connect_target(b"CONNECT mesh.sam.alt:80 HTTP/1.1\r\n\r\n", set())
        == "mesh.sam.alt:80"
    )


@pytest.mark.parametrize("host", ["*", "*.test", "1.1.1.1", "localhost", "127.1", "host/evil"])
def test_policy_refuses_ambiguous_or_literal_hosts(host):
    with pytest.raises(ValueError):
        boundary.validate_names([host])


def test_credential_deadline_rejects_missing_or_expired(tmp_path):
    with pytest.raises((ValueError, OSError)):
        boundary.credential_deadline(tmp_path / "missing", now=100)
    import base64
    import json

    path = tmp_path / "jwt"
    payload = base64.urlsafe_b64encode(json.dumps({"exp": 110}).encode()).decode().rstrip("=")
    path.write_text("e30." + payload + ".c2ln")
    with pytest.raises(ValueError):
        boundary.credential_deadline(path, now=100)


def test_canonical_mesh_underscore_is_preserved():
    wire = b"CONNECT my_service.mcp.sam.alt:80 HTTP/1.1\r\n\r\n"
    assert boundary.connect_target(wire, set()) == "my_service.mcp.sam.alt:80"


def test_published_tun2connect_go_request_wire():
    # BoundaryClient v0.0.1 calls net/http.Request.Write, whose default UA is fixed.
    wire = b"CONNECT allowed.test:18081 HTTP/1.1\r\nHost: allowed.test:18081\r\nUser-Agent: Go-http-client/1.1\r\n\r\n"
    assert boundary.connect_target(wire, {"allowed.test"}) == "allowed.test:18081"


@pytest.mark.parametrize(
    "extra",
    [
        b"User-Agent: agent-controlled",
        b"Transfer-Encoding: chunked",
        b"Connection: Upgrade",
        b"Authorization: Bearer not-permitted",
    ],
)
def test_no_general_header_extension(extra):
    wire = b"CONNECT allowed.test:80 HTTP/1.1\r\nHost: allowed.test:80\r\n" + extra + b"\r\n\r\n"
    with pytest.raises(ValueError):
        boundary.connect_target(wire, {"allowed.test"})
