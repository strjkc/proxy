import types

from proxy.connection import Connection
import pytest
from dataclasses import dataclass

@dataclass
class Case[T]:
    id: str
    raw: bytes
    expected: T


@dataclass
class BodyCase(Case):
    content_type: str

exception_cases = [
    Case(
        id="empty socket",
        raw=b"",
        expected=ValueError
    ),
    Case(
        id="partial headers",
        raw=b"POST / api HTTP/1.1\r\nHost: 127.0.0.1",
        expected=ValueError
    ),
]
various = {
   "headers_only":{
       "data":  b"POST /api HTTP/1.1\r\n" 
                b"Host:127.0.0.1:8080\r\n" 
                b"User-Agent:ur mum\r\n" 
                b"Accept:*/*\r\n" 
                b"Accept-Encoding:gzip, deflate, br\r\n\r\n",
       "expected": {
            "Method": "POST",
            "Path": "/api",
            "Proto": "HTTP/1.1",
            "Host": "127.0.0.1:8080",
            "User-Agent": "ur mum",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
        }
   },
    "full_msg": {
        "data": b"POST /api HTTP/1.1\r\n"
        b"Host:127.0.0.1:8080\r\n" 
        b"User-Agent:ur mum\r\n" 
        b"Accept:*/*\r\n" 
        b"Accept-Encoding:gzip, deflate, br\r\n"
        b"Content-Type:application/json\r\n" 
        b"Content-Length:32\r\n\r\n" 
        b'{"id":23, "username":"testuser"}'
    ,
    "expected":{"headers":{
        "Method": "POST",
        "Path": "/api",
        "Proto": "HTTP/1.1",
        "Host": "127.0.0.1:8080",
        "User-Agent": "ur mum",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/json",
        "Content-Length": "32",
        },
        "body": {"id": 23, "username": "testuser"}
    }
    },
    "full_msg_headers_only_second":{
        "data": b"POST /api HTTP/1.1\r\n"
        b"Host:127.0.0.1:8080\r\n" 
        b"User-Agent:ur mum\r\n" 
        b"Accept:*/*\r\n" 
        b"Accept-Encoding:gzip, deflate, br\r\n" 
        b"Content-Type:application/json\r\n" 
        b"Content-Length:32\r\n\r\n" 
        b'{"id":23, "username":"testuser"}' 
        b"POST /api HTTP/1.1\r\n" 
        b"Host:127.0.0.1:8080\r\n" 
        b"User-Agent:ur mum\r\n" 
        b"Accept:*/*\r\n" 
        b"Accept-Encoding:gzip, deflate, br\r\n\r\n",
        "expected":{
            "headers":{
                "Method": "POST",
                "Path": "/api",
                "Proto": "HTTP/1.1",
                "Host": "127.0.0.1:8080",
                "User-Agent": "ur mum",
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate, br",
                "Content-Type": "application/json",
                "Content-Length": "32",
        }, "body":
                {"id": 23, "username": "testuser"}},
        "expected2":{
        "Method": "POST",
        "Path": "/api",
        "Proto": "HTTP/1.1",
        "Host": "127.0.0.1:8080",
        "User-Agent": "ur mum",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
    }
    },
    "full_msg_partial_body_second":{
        "data":b"POST /api HTTP/1.1\r\n" 
           b"Host:127.0.0.1:8080\r\n" 
           b"User-Agent:ur mum\r\n" 
           b"Accept:*/*\r\n" 
           b"Accept-Encoding:gzip, deflate, br\r\n" 
           b"Content-Type:application/json\r\n" 
           b"Content-Length:32\r\n\r\n" 
           b'{"id":23, "username":"testuser"}' 
           b"POST /api HTTP/1.1\r\n" 
           b"Host:127.0.0.1:8080\r\n" 
           b"User-Agent:ur mum\r\n" 
           b"Accept:*/*\r\n" 
           b"Accept-Encoding:gzip, deflate, br\r\n" 
           b"Content-Type:application/json\r\n" 
           b"Content-Length:32\r\n\r\n" 
           b'{"id":23, "userna',
        "expected": {"headers":{
        "Method": "POST",
        "Path": "/api",
        "Proto": "HTTP/1.1",
        "Host": "127.0.0.1:8080",
        "User-Agent": "ur mum",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/json",
        "Content-Length": "32",
    }, "body": {"id": 23, "username": "testuser"}}
    },
    "full_msg_partial_headers_second":{
        "data": b"POST /api HTTP/1.1\r\n" 
           b"Host:127.0.0.1:8080\r\n"
           b"User-Agent:ur mum\r\n" 
           b"Accept:*/*\r\n" 
           b"Accept-Encoding:gzip, deflate, br\r\n"
           b"Content-Type:application/json\r\n" 
           b"Content-Length:32\r\n\r\n" 
           b'{"id":23, "username":"testuser"}'
           b"POST /api HTTP/1.1\r\n" 
           b"Host:127.0.0.1:8080\r\n" 
           b"User-Agent:ur mum\r\n" 
           b"Accept:*/*\r\n" 
           b"Accept-Encoding:gzip, deflate, br\r\n"
           b"Content-Type:application/json\r\n",
        "expected": {"headers":{
        "Method": "POST",
        "Path": "/api",
        "Proto": "HTTP/1.1",
        "Host": "127.0.0.1:8080",
        "User-Agent": "ur mum",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/json",
        "Content-Length": "32",
    }, "body": {"id": 23, "username": "testuser"}}
    },
    "full_two_msg":{
        "data":b"POST /api HTTP/1.1\r\n" \
           b"Host:127.0.0.1:8080\r\n" \
           b"User-Agent:ur mum\r\n" \
           b"Accept:*/*\r\n" \
           b"Accept-Encoding:gzip, deflate, br\r\n" \
           b"Content-Type:application/json\r\n" \
           b"Content-Length:32\r\n\r\n" \
           b'{"id":23, "username":"testuser"}' \
           b"POST /api HTTP/1.1\r\n" \
           b"Host:127.0.0.1:8080\r\n" \
           b"User-Agent:ur mum\r\n" \
           b"Accept:*/*\r\n" \
           b"Accept-Encoding:gzip, deflate, br\r\n" \
           b"Content-Type:application/json\r\n" \
           b"Content-Length:32\r\n\r\n" \
           b'{"id":23, "username":"testuser"}',
        "expected": {"headers":{
        "Method": "POST",
        "Path": "/api",
        "Proto": "HTTP/1.1",
        "Host": "127.0.0.1:8080",
        "User-Agent": "ur mum",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/json",
        "Content-Length": "32",
    }, "body": {"id": 23, "username": "testuser"}}
    }
    }
class TestSocket:
    def __init__(self, data:bytes):
        self.buffer = data

    def recv(self, n):
        ret = self.buffer[:n]
        self.buffer = self.buffer[n:]
        return ret

#TODO: send response
#TODO: send request
#TODO: large heraders
@pytest.mark.parametrize("case", exception_cases, ids=[case.id for case in exception_cases])
def test_exception_cases(case):
    sock = TestSocket(case.raw)
    conn = Connection(sock, 100, 100)
    cb = lambda a,b : print("testing")
    with pytest.raises(case.expected):
        conn.receive_req(cb)

def test_headers_only():
    data = various.get("headers_only").get("data")
    expected = various.get("headers_only").get("expected")
    sock = TestSocket(data)
    conn = Connection(sock, 100, 100)
    cb = lambda a,b : print("testing")
    headers, body = conn.receive_req(cb)
    assert headers == expected

def test_full_msg():
    data = various.get("full_msg").get("data")
    expected = various.get("full_msg").get("expected")
    sock = TestSocket(data)
    conn = Connection(sock, 100, 100)
    cb = lambda a,b : print("testing")
    headers, body = conn.receive_req(cb)
    assert headers == expected["headers"]
    assert body == expected["body"]


def test_full_msg_headers_only_second():
    data = various.get("full_msg_headers_only_second").get("data")
    expected = various.get("full_msg_headers_only_second").get("expected")
    expected2 = various.get("full_msg_headers_only_second").get("expected2")
    sock = TestSocket(data)
    conn = Connection(sock, 100, 100)
    cb = lambda a,b : print("testing")
    headers, body = conn.receive_req(cb)
    assert headers == expected["headers"]
    assert body == expected["body"]
    assert len(conn.inb) > 0
    headers, body = conn.receive_req(cb)
    assert headers == expected2
    assert not body
    assert len(conn.inb) == 0

def test_full_msg_partial_body_second():
    data = various.get("full_msg_partial_body_second").get("data")
    expected = various.get("full_msg_partial_body_second").get("expected")
    sock = TestSocket(data)
    conn = Connection(sock, 100, 100)
    cb = lambda a,b : print("testing")
    headers, body = conn.receive_req(cb)
    assert headers == expected["headers"]
    assert body == expected["body"]
    with pytest.raises(ValueError):
        conn.receive_req(cb)

def test_full_msg_partial_headers_second():
    data = various.get("full_msg_partial_headers_second").get("data")
    expected = various.get("full_msg_partial_headers_second").get("expected")
    sock = TestSocket(data)
    conn = Connection(sock, 100, 100)
    cb = lambda a,b : print("testing")
    headers, body = conn.receive_req(cb)
    assert headers == expected["headers"]
    assert body == expected["body"]
    with pytest.raises(ValueError):
        conn.receive_req(cb)


def test_full_two_msg():
    data = various.get("full_two_msg").get("data")
    expected = various.get("full_two_msg").get("expected")
    sock = TestSocket(data)
    conn = Connection(sock, 100, 100)
    cb = lambda a,b : print("testing")
    headers, body = conn.receive_req(cb)
    assert headers == expected["headers"]
    assert body == expected["body"]
    headers, body = conn.receive_req(cb)
    assert headers == expected["headers"]
    assert body == expected["body"]