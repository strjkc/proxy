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

class TestSocket:
    def __init__(self, data:bytes):
        self.buffer = data

    def recv(self, n):
        ret = self.buffer[:n]
        self.buffer = self.buffer[n:]
        return ret
    #receive req
    #    empty socket
    #    partial headers
    #    headers only in socket - ok
    #    headers and partial body - we have headers, satte is parsing body, buffer is not empty
    #    full socket - parsed message
    #    more than one message in the socket:
    #    one full one headers only - parsed message, second itteration, headers only, body is none, buffer is empty
    #    one full one headers and partial body - parsed message, second itteration, satte is parsing body, buffer is not empty
    #    two full messages - two messages, two itterations
    #    if we are parsing too long we expect some error
    #    we return current state to the manager and reset state
    #receive resp
    #    its the same the only diff is the parser method
    #send req
    #    we have a message in the buffer, we serailize another one, two messages in the buffer?
    #    only diff is how we serialize
    #send resp
@pytest.mark.parametrize("case", exception_cases, ids=[case.id for case in exception_cases])
def test_exception_cases(case):
    sock = TestSocket(case.raw)
    conn = Connection(sock, 100, 100)
    cb = lambda a,b : print("testing")
    with pytest.raises(case.expected):
        conn.receive_req(cb)

def test_headers_only():
    data = b"POST /api HTTP/1.1\r\n" \
        b"Host:127.0.0.1:8080\r\n" \
        b"User-Agent:ur mum\r\n" \
        b"Accept:*/*\r\n" \
        b"Accept-Encoding:gzip, deflate, br\r\n" \
        b"Content-Type:application/json\r\n" \
        b"Content-Length:48\r\n\r\n"
    expected = {
        "Method": "POST",
        "Path": "/api",
        "Proto": "HTTP/1.1",
        "Host": "127.0.0.1:8080",
        "User-Agent": "ur mum",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/json",
        "Content-Length": "48",
    }
    sock = TestSocket(data)
    conn = Connection(sock, 100, 100)
    cb = lambda a,b : print("testing")
    headers, body = conn.receive_req(cb)
    assert headers == expected

def test_full_msg():
    data = b"POST /api HTTP/1.1\r\n" \
        b"Host:127.0.0.1:8080\r\n" \
        b"User-Agent:ur mum\r\n" \
        b"Accept:*/*\r\n" \
        b"Accept-Encoding:gzip, deflate, br\r\n" \
        b"Content-Type:application/json\r\n" \
        b"Content-Length:32\r\n\r\n" \
        b'{"id":23, "username":"testuser"}'
    expected = {"headers":{
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
    sock = TestSocket(data)
    conn = Connection(sock, 100, 100)
    cb = lambda a,b : print("testing")
    headers, body = conn.receive_req(cb)
    assert headers == expected["headers"]
    assert body == expected["body"]