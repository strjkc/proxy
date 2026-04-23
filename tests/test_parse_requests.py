import parser
import pytest
from dataclasses import dataclass


@dataclass
class Case:
    id: str
    raw: bytes
    expected: dict


CASES_VALID = [
    Case(
        id="valid request",
        raw=b"POST /api HTTP/1.1\r\n"
        b"Host: 127.0.0.1:8080\r\n"
        b"User-Agent: ur mum\r\n"
        b"Accept: */*\r\n"
        b"Accept-Encoding: gzip, deflate, br\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 48\r\n",
        expected={
            "Method": "POST",
            "Path": "/api",
            "Proto": "HTTP/1.1",
            "Host": "127.0.0.1:8080",
            "User-Agent": "ur mum",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/json",
            "Content-Length": "48",
        },
    ),
    Case(
        id="valid request, lower caps",
        raw=b"post /api HTTP/1.1\r\n"
        b"host: 127.0.0.1:8080\r\n"
        b"user-agent: ur mum\r\n"
        b"accept: */*\r\n"
        b"accept-encoding: gzip, deflate, br\r\n"
        b"content-type: application/json\r\n"
        b"content-length: 48\r\n",
        expected={
            "Method": "POST",
            "Path": "/api",
            "Proto": "HTTP/1.1",
            "Host": "127.0.0.1:8080",
            "User-Agent": "ur mum",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/json",
            "Content-Length": "48",
        },
    ),
]

CASES_INVALID = [
    Case(
        id="invalid method",
        raw=(
            b"/api POST HTTP/1.1\r\n"
            b"Host: 127.0.0.1:8080\r\n"
            b"User-Agent: ur mum\r\n"
            b"Accept: */*\r\n"
            b"Accept-Encoding: gzip, deflate, br\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 48\r\n"
        ),
        expected=pytest.raises(ValueError),
    ),
    Case(
        id="missing_first_line",
        raw=(
            b"Host: 127.0.0.1:8080\r\n"
            b"User-Agent: ur mum\r\n"
            b"Accept: */*\r\n"
            b"Accept-Encoding: gzip, deflate, br\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 48\r\n"
        ),
        expected={},
    ),
    Case(
        id="invalid_path",
        raw=(
            b"POST HTTP/1.1 /api\r\n"
            b"Host: 127.0.0.1:8080\r\n"
            b"User-Agent: ur mum\r\n"
            b"Accept: */*\r\n"
            b"Accept-Encoding: gzip, deflate, br\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 48\r\n"
        ),
        expected={},
    ),
    Case(
        id="invalid_protocol",
        raw=(
            b"POST HTTP/1.1 /api\r\n"
            b"Host: 127.0.0.1:8080\r\n"
            b"User-Agent: ur mum\r\n"
            b"Accept: */*\r\n"
            b"Accept-Encoding: gzip, deflate, br\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 48\r\n"
        ),
        expected={},
    ),
    Case(
        id="missing_host",
        raw=(
            b"POST /api HTTP/1.1\r\n"
            b"User-Agent: ur mum\r\n"
            b"Accept: */*\r\n"
            b"Accept-Encoding: gzip, deflate, br\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 48\r\n"
        ),
        expected={},
    ),
    Case(
        id="no_header_delimiter",
        raw=(
            b"POST /api HTTP/1.1\r\n"
            b"Host: 127.0.0.1:8080\r\n"
            b"User-Agent: ur mum\r\n"
            b"Accept: */*\r\n"
            b"Accept-Encoding: gzip, deflate, br\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 48\r\n"
        ),
        expected={},
    ),
    Case(
        id="oversized header",
        raw=(
            b"GET /example/path HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: CustomClient/1.0 (X11; Linux x86_64) ReverseProxyTestingSuite/2026.02\r\n"
            b"Accept: application/json, text/plain, */*;q=0.8\r\n"
            b"X-Long-Debug-Header: ThisIsAnExtremelyLongHeaderValueUsedForTestingParserLimitsAndBufferHandling1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ\r\n"
            b"X-Correlation-ID: 9f8d7c6b5a4e3d2c1b0a9e8d7c6b5a4e\r\n"
            b"X-Forwarded-For: 203.0.113.42, 198.51.100.17, 192.0.2.88\r\n"
            b"X-Custom-Metadata: key1=value1; key2=value2; key3=value3; key4=value4; key5=value5\r\n"
            b"Connection: keep-alive\r\n"
            + b"X-Oversized-Header: "
            + (b"A" * 9200)
            + b"\r\n"
        ),
        expected={},
    ),
]


@pytest.mark.parametrize("case", CASES_VALID, ids=[case.id for case in CASES_VALID])
def test_parse_request(case):
    headers = parser.parse_request_headers(case.raw, ["GET", "POST", "post"])
    assert headers == case.expected


@pytest.mark.parametrize("case", CASES_INVALID, ids=[case.id for case in CASES_INVALID])
def test_invalid_method(case):
    with pytest.raises(ValueError):
        parser.parse_request_headers(case.raw, ["GET", "POST"])
