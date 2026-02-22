import pytest
import pytest_mock
from libproxy import Message


def test_create_request(mocker):
    socket = mocker.Mock()
    socket.getpeername.return_value = ("127.0.0.1", 8181)
    message = Message(socket, None, None, None, None, None, None)
    message.req_headers = {
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
    message.req_body = {"username": "Testing", "password": "topsecret"}
    t = (
        b"POST /api HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: ur mum\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nContent-Type: application/json\r\nContent-Length: 48\r\nX-Forwarded-For: 127.0.0.1"
        + b'\r\n\r\n{"username": "Testing", "password": "topsecret"}'
    )
    print(message)
    message._serialize_req()
    print(f"out buffer {message.s_outb}")
    print(f"expected out buffer {t}")
    assert message.s_outb == t
