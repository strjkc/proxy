from libproxy import Message
import pytest


def test_parse_request():
    m = Message(None, None, None, None, None, None, None)
    expected_headers = {
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
    expected_body = {"username": "Testing", "password": "topsecret"}
    t = b'POST /api HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: ur mum\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nContent-Type: application/json\r\nContent-Length: 48\r\n\r\n{"username": "Testing", "password": "topsecret"}'
    m.c_inb = t
    m._parse_request(t)
    assert m.req_headers == expected_headers
    assert m.req_body == expected_body


def test_invalid_method():
    m = Message(None, None, None, None, None, None, None)
    t = b'/api POST HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: ur mum\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nContent-Type: application/json\r\nContent-Length: 48\r\n\r\n{"username": "Testing", "password": "topsecret"}'
    m.c_inb = t
    with pytest.raises(ValueError):
        m._parse_request(t)


def test_parse_request_missing_first_line():
    m = Message(None, None, None, None, None, None, None)
    t = b'Host: 127.0.0.1:8080\r\nUser-Agent: ur mum\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nContent-Type: application/json\r\nContent-Length: 48\r\n\r\n{"username": "Testing", "password": "topsecret"}'
    m.c_inb = t
    with pytest.raises(ValueError):
        m._parse_request(t)


def test_parse_request_invalid_path():
    m = Message(None, None, None, None, None, None, None)
    t = b'POST HTTP/1.1 /api\r\nHost: 127.0.0.1:8080\r\nUser-Agent: ur mum\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nContent-Type: application/json\r\nContent-Length: 48\r\n\r\n{"username": "Testing", "password": "topsecret"}'
    m.c_inb = t
    with pytest.raises(ValueError):
        m._parse_request(t)


def test_parse_request_invalid_protocol():
    m = Message(None, None, None, None, None, None, None)
    t = b'POST HTTP/1.1 /api\r\nHost: 127.0.0.1:8080\r\nUser-Agent: ur mum\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nContent-Type: application/json\r\nContent-Length: 48\r\n\r\n{"username": "Testing", "password": "topsecret"}'
    m.c_inb = t
    with pytest.raises(ValueError):
        m._parse_request(t)


@pytest.mark.skip
def test_parse_request_missing_host():
    m = Message(None, None, None, None, None, None, None)
    t = b'POST /api HTTP/1.1\r\nUser-Agent: ur mum\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nContent-Type: application/json\r\nContent-Length: 48\r\n\r\n{"username": "Testing", "password": "topsecret"}'
    m.c_inb = t
    with pytest.raises(ValueError):
        m._parse_request(t)


@pytest.mark.skip
def test_no_header_delimiter():
    m = Message(None, None, None, None, None, None, None)
    t = b"POST /api HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: ur mum\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nContent-Type: application/json\r\nContent-Length: 48\r\n"
    m.c_inb = t
    m._parse_request(t)
    with pytest.raises(ValueError):
        m._parse_request(t)


def test_long_headers():
    m = Message(None, None, None, None, None, None, None)
    long_str = b"A" * 9200
    f = b"X-Oversized-Header: " + long_str + b"\r\n"
    t = (
        b"GET /example/path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: CustomClient/1.0 (X11; Linux x86_64) ReverseProxyTestingSuite/2026.02\r\nAccept: application/json, text/plain, */*;q=0.8\r\nX-Long-Debug-Header: ThisIsAnExtremelyLongHeaderValueUsedForTestingParserLimitsAndBufferHandling1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ\r\nX-Correlation-ID: 9f8d7c6b5a4e3d2c1b0a9e8d7c6b5a4e\r\nX-Forwarded-For: 203.0.113.42, 198.51.100.17, 192.0.2.88\r\nX-Custom-Metadata: key1=value1; key2=value2; key3=value3; key4=value4; key5=value5\r\nConnection: keep-alive\r\n"
        + f
    )
    m.c_inb = t
    with pytest.raises(ValueError):
        m._parse_request(t)
