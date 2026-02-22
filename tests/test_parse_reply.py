from libproxy import Message
import pytest

import libproxy


@pytest.fixture
def message(mocker):
    socket_close = mocker.patch("libproxy.socket.socket")
    socket_close.close.return_value = None
    selector = mocker.Mock()
    selector.unregister.return_value = None
    return Message(None, selector, None, None, None, None, None)


def test_parse_response(message):
    expected_headers = {
        "Code": "200",
        "Message": "OK",
        "Proto": "HTTP/1.1",
        "Host": "127.0.0.1:8080",
        "User-Agent": "ur mum",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/json",
        "Content-Length": "48",
    }
    expected_body = {"username": "Testing", "password": "topsecret"}
    t = b'HTTP/1.1 200 OK\r\nHost: 127.0.0.1:8080\r\nUser-Agent: ur mum\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nContent-Type: application/json\r\nContent-Length: 48\r\n\r\n{"username": "Testing", "password": "topsecret"}'
    message.s_inb = t
    message._parse_response(t)
    assert message.reply_headers == expected_headers
    assert message.reply_body == expected_body


@pytest.mark.skip(reason="Not implemented")
def test_invalid_code(message):
    t = b'HTTP/1.1 800 OK\r\nHost: 127.0.0.1:8080\r\nUser-Agent: ur mum\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nContent-Type: application/json\r\nContent-Length: 48\r\n\r\n{"username": "Testing", "password": "topsecret"}'
    message.s_inb = t
    with pytest.raises(ValueError):
        message._parse_response(t)


def test_parse_response_missing_first_line(message):
    t = b'Host: 127.0.0.1:8080\r\nUser-Agent: ur mum\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nContent-Type: application/json\r\nContent-Length: 48\r\n\r\n{"username": "Testing", "password": "topsecret"}'
    message.s_inb = t
    with pytest.raises(ValueError):
        message._parse_response(t)


def test_parse_response_invalid_protocol(message):
    t = b'BLA 200 OK\r\nHost: 127.0.0.1:8080\r\nUser-Agent: ur mum\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nContent-Type: application/json\r\nContent-Length: 48\r\n\r\n{"username": "Testing", "password": "topsecret"}'
    message.s_inb = t
    with pytest.raises(ValueError):
        message._parse_response(t)


def test_long_headers(message):
    long_str = b"A" * 9200
    f = b"X-Oversized-Header: " + long_str + b"\r\n"
    t = (
        b"HTTP/1.1 200 OK\r\nHost: example.com\r\nUser-Agent: CustomClient/1.0 (X11; Linux x86_64) ReverseProxyTestingSuite/2026.02\r\nAccept: application/json, text/plain, */*;q=0.8\r\nX-Long-Debug-Header: ThisIsAnExtremelyLongHeaderValueUsedForTestingParserLimitsAndBufferHandling1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ\r\nX-Correlation-ID: 9f8d7c6b5a4e3d2c1b0a9e8d7c6b5a4e\r\nX-Forwarded-For: 203.0.113.42, 198.51.100.17, 192.0.2.88\r\nX-Custom-Metadata: key1=value1; key2=value2; key3=value3; key4=value4; key5=value5\r\nConnection: keep-alive\r\n"
        + f
    )
    message.s_inb = t
    with pytest.raises(ValueError):
        message._parse_response(t)
