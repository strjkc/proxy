from json import JSONDecodeError
from proxy.parser import Parser
import pytest
from dataclasses import dataclass

#TODO: serialization
@dataclass
class Case[T]:
    id: str
    raw: bytes
    expected: T


@dataclass
class BodyCase(Case):
    content_type: str


REQ_HEADER_CASES_VALID = [
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
        id="valid request, no spaces after :",
        raw=b"POST /api HTTP/1.1\r\n"
        b"Host:127.0.0.1:8080\r\n"
        b"User-Agent:ur mum\r\n"
        b"Accept:*/*\r\n"
        b"Accept-Encoding:gzip, deflate, br\r\n"
        b"Content-Type:application/json\r\n"
        b"Content-Length:48\r\n",
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
        id="valid request, duplicate line delimiters",
        raw=b"POST /api HTTP/1.1\r\n\r\n"
        b"Host: 127.0.0.1:8080\r\n\r\n"
        b"User-Agent: ur mum\r\n\r\n"
        b"Accept: */*\r\n\r\n"
        b"Accept-Encoding: gzip, deflate, br\r\n\r\n"
        b"Content-Type: application/json\r\n\r\n"
        b"Content-Length: 48\r\n\r\n",
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
    Case(
        id="valid request, mix caps",
        raw=b"post /api HTTP/1.1\r\n"
        b"hOst: 127.0.0.1:8080\r\n"
        b"usEr-agent: ur mum\r\n"
        b"accepT: */*\r\n"
        b"Accept-encoding: gzip, deflate, br\r\n"
        b"content-type: application/json\r\n"
        b"coNtent-Length: 48\r\n",
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

REQ_HEADER_CASES_INVALID = [
    Case(
        id="empty request",
        raw=(b""),
        expected={},
    ),
    Case(
        id="invalid delimiters",
        raw=(
            b"/api POST HTTP/1.1\r\n"
            b"Host; 127.0.0.1:8080\r\n"
            b"User-Agent; ur mum\r\n"
            b"Accept; */*\r\n"
            b"Accept-Encoding; gzip, deflate, br\r\n"
            b"Content-Type; application/json\r\n"
            b"Content-Length; 48\r\n"
        ),
        expected={},
    ),
    Case(
        id="invalid line breaks",
        raw=(
            b"/api POST HTTP/1.1\n"
            b"Host; 127.0.0.1:8080\n"
            b"User-Agent; ur mum\n"
            b"Accept; */*\n"
            b"Accept-Encoding; gzip, deflate, br\n"
            b"Content-Type; application/json\n"
            b"Content-Length; 48\n"
        ),
        expected={},
    ),
    Case(
        id="no line breaks",
        raw=(
            b"/api POST HTTP/1.1"
            b"Host; 127.0.0.1:8080"
            b"User-Agent; ur mum"
            b"Accept; */*"
            b"Accept-Encoding; gzip, deflate, br"
            b"Content-Type; application/json"
            b"Content-Length; 48"
        ),
        expected={},
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
]

REQ_BODY_CASES_VALID = [
    BodyCase(
        id="valid json can be parsed",
        raw=b'{"username": "testuser", "id":1, "password": "shhhhhh_secret", "created_at": "2026-04-23 10:00:00"}',
        content_type="application/json",
        expected={
            "username": "testuser",
            "id": 1,
            "password": "shhhhhh_secret",
            "created_at": "2026-04-23 10:00:00",
        },
    ),
    BodyCase(
        id="valid text can be parsed",
        raw=b"<h1>Some Raw Html Text</h1>",
        content_type="text/html",
        expected="<h1>Some Raw Html Text</h1>",
    ),
]

REQ_BODY_CASES_INVALID = [
    BodyCase(
        id="invalid content type can't be parsed",
        raw=b'{"username": "testuser", "id":1, "password": "shhhhhh_secret", "created_at": "2026-04-23 10:00:00"}',
        content_type="application/javascript",
        expected=ValueError,
    ),
    BodyCase(
        id="partial body can't be parsed",
        raw=b'{"username": "testuser", "id":1, "password": "shhhhhh_secret"',
        content_type="application/json",
        expected=ValueError,
    ),
    BodyCase(
        id="regular text can't be parsed when content_type is json",
        raw=b'"username": "testuser", "id":1, "password": "shhhhhh_secret"',
        content_type="application/json",
        expected=JSONDecodeError,
    ),
    BodyCase(
        id="invalid json can't be parsed",
        raw=b'{"username": "testuser", "id":1, "password": "shhhhhh_secret" "created_at": "2026-04-23 10:00:00"}',
        content_type="application/json",
        expected=JSONDecodeError,
    ),
]


RESP_HEADER_CASES_VALID = [
    Case(
        id="valid request 200",
        raw=b"HTTP/1.1 200 OK\r\n"
        b"Host: 127.0.0.1:8080\r\n"
        b"User-Agent: ur mum\r\n"
        b"Accept: */*\r\n"
        b"Accept-Encoding: gzip, deflate, br\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 48\r\n",
        expected={
            "Message": "OK",
            "Code": "200",
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
        id="valid request 404",
        raw=b"HTTP/1.1 404 Not Found\r\n"
        b"Host: 127.0.0.1:8080\r\n"
        b"User-Agent: ur mum\r\n"
        b"Accept: */*\r\n"
        b"Accept-Encoding: gzip, deflate, br\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 48\r\n",
        expected={
            "Message": "Not Found",
            "Code": "404",
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
        id="valid request, no spaces after :",
        raw=b"HTTP/1.1 200 OK\r\n"
        b"Host:127.0.0.1:8080\r\n"
        b"User-Agent:ur mum\r\n"
        b"Accept:*/*\r\n"
        b"Accept-Encoding:gzip, deflate, br\r\n"
        b"Content-Type:application/json\r\n"
        b"Content-Length:48\r\n",
        expected={
            "Message": "OK",
            "Code": "200",
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
        id="valid request, duplicate line delimiters",
        raw=b"HTTP/1.1 200 OK\r\n\r\n"
        b"Host: 127.0.0.1:8080\r\n\r\n"
        b"User-Agent: ur mum\r\n\r\n"
        b"Accept: */*\r\n\r\n"
        b"Accept-Encoding: gzip, deflate, br\r\n\r\n"
        b"Content-Type: application/json\r\n\r\n"
        b"Content-Length: 48\r\n\r\n",
        expected={
            "Message": "OK",
            "Code": "200",
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
        raw=b"HTTP/1.1 200 ok\r\n"
        b"host: 127.0.0.1:8080\r\n"
        b"user-agent: ur mum\r\n"
        b"accept: */*\r\n"
        b"accept-encoding: gzip, deflate, br\r\n"
        b"content-type: application/json\r\n"
        b"content-length: 48\r\n",
        expected={
            "Message": "ok",
            "Code": "200",
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
        id="valid request, mix caps",
        raw=b"HTTP/1.1 200 OK\r\n"
        b"hOst: 127.0.0.1:8080\r\n"
        b"usEr-agent: ur mum\r\n"
        b"accepT: */*\r\n"
        b"Accept-encoding: gzip, deflate, br\r\n"
        b"content-type: application/json\r\n"
        b"coNtent-Length: 48\r\n",
        expected={
            "Message": "OK",
            "Code": "200",
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

RESP_HEADER_CASES_INVALID = [
    Case(
        id="empty request",
        raw=(b""),
        expected={},
    ),
    Case(
        id="invalid delimiters",
        raw=(
            b"HTTP/1.1 200 OK\r\n"
            b"Host; 127.0.0.1:8080\r\n"
            b"User-Agent; ur mum\r\n"
            b"Accept; */*\r\n"
            b"Accept-Encoding; gzip, deflate, br\r\n"
            b"Content-Type; application/json\r\n"
            b"Content-Length; 48\r\n"
        ),
        expected={},
    ),
    Case(
        id="invalid line breaks",
        raw=(
            b"HTTP/1.1 200 OK\n"
            b"Host; 127.0.0.1:8080\n"
            b"User-Agent; ur mum\n"
            b"Accept; */*\n"
            b"Accept-Encoding; gzip, deflate, br\n"
            b"Content-Type; application/json\n"
            b"Content-Length; 48\n"
        ),
        expected={},
    ),
    Case(
        id="no line breaks",
        raw=(
            b"HTTP/1.1 200 OK"
            b"Host; 127.0.0.1:8080"
            b"User-Agent; ur mum"
            b"Accept; */*"
            b"Accept-Encoding; gzip, deflate, br"
            b"Content-Type; application/json"
            b"Content-Length; 48"
        ),
        expected={},
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
]


@pytest.mark.parser
@pytest.mark.req_parser
@pytest.mark.parametrize(
    "case", REQ_HEADER_CASES_VALID, ids=[case.id for case in REQ_HEADER_CASES_VALID]
)
def test_parse_request_headers(case):
    headers = Parser.parse_request_headers(case.raw, ["GET", "POST"])
    assert headers == case.expected


@pytest.mark.parser
@pytest.mark.resp_parser
@pytest.mark.parametrize(
    "case", RESP_HEADER_CASES_VALID, ids=[case.id for case in RESP_HEADER_CASES_VALID]
)
def test_parse_response_headers(case):
    headers = Parser.parse_response_headers(case.raw)
    assert headers == case.expected


@pytest.mark.parser
@pytest.mark.parametrize(
    "case", REQ_HEADER_CASES_INVALID, ids=[case.id for case in REQ_HEADER_CASES_INVALID]
)
def test_invalid_method(case):
    with pytest.raises(ValueError):
        Parser.parse_request_headers(case.raw, ["GET", "POST"])


@pytest.mark.parser
@pytest.mark.parametrize(
    "case", REQ_BODY_CASES_VALID, ids=[case.id for case in REQ_BODY_CASES_VALID]
)
def test_body_parsed(case: BodyCase):
    parsed = Parser.parse_body(case.raw, case.content_type)
    assert parsed == case.expected


@pytest.mark.parser
@pytest.mark.parametrize(
    "case", REQ_BODY_CASES_INVALID, ids=[case.id for case in REQ_BODY_CASES_INVALID]
)
def test_invalid_body(case: BodyCase):
    with pytest.raises(case.expected):
        Parser.parse_body(case.raw, case.content_type)
