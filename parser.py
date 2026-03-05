import logging
import json

logger = logging.getLogger(__name__)


def parse_request_headers(headers: bytes, valid_methods: list) -> dict:
    logger.debug("parsing headers")
    parsed = {}
    h_string = headers.decode()
    first_line, *arr = h_string.split("\r\n")
    logger.debug(f"first line: {first_line}")
    logger.debug(f"rest: {arr}")
    f_arr = first_line.split(" ")
    if len(f_arr) != 3:
        raise ValueError("Invalid headers")
    method, path, protocol = _validate_request_headers(f_arr, valid_methods)
    parsed["Method"] = method
    parsed["Path"] = path
    parsed["Proto"] = protocol
    for header in arr:
        k, v = header.split(": ")
        k = _normalize_header_key(k)
        parsed[k] = v
    return parsed


def parse_response_headers(headers: bytes) -> dict:
    parsed = {}
    h_string = headers.decode()
    first_line, *arr = h_string.split("\r\n")
    # print(f"first line in response: {first_line}")
    f_arr = first_line.split(" ")
    if len(f_arr) > 3:
        rest = " ".join(f_arr[2:])
        f_arr = f_arr[:2]
        f_arr.append(rest)
    logger.debug(f_arr)
    if len(f_arr) != 3:
        raise ValueError("Invalid headers")
    proto, code, message = _validate_response_headers(f_arr)
    parsed["Proto"] = proto
    parsed["Code"] = code
    parsed["Message"] = message
    for header in arr:
        k, v = header.split(": ")
        k = _normalize_header_key(k)
        parsed[k] = v
    return parsed


def _normalize_header_key(key):
    f = key.lower()
    if "-" in f:
        return "-".join([part.capitalize() for part in f.split("-")])
    return f.capitalize()


def parse_body(body: bytes, content_type: str):
    logger.debug(f"content type: {content_type}")
    # print(f"parsing body of len: {len(body)}")
    if "application/json" in content_type:
        b = body.decode()
        logger.debug(f"This should be body as string: \n {type(b)}")
        return json.loads(b)
    elif "text/html" in content_type:
        return body.decode()
    raise ValueError("Invalid body content type")


def _validate_response_headers(headers_arr):
    proto, code, message = headers_arr
    if proto != "HTTP/1.1":
        raise ValueError("Invalid Protocol")
    return proto, code, message


# parser should not validate - move to Connection
def _validate_request_headers(headers_arr, valid_methods):
    method, path, protocol = headers_arr
    logger.debug(method, path, protocol)
    if method not in valid_methods:
        raise ValueError("Invalid HTTP Method Used")
    if protocol != "HTTP/1.1":
        raise ValueError("Invalid Protocol")
    if "/" not in path:
        raise ValueError("Invalid Path Format")
    return method, path, protocol


def serialize_req(headers: dict, body, hostname, peername):
    logger.debug("serializing request")
    # print(f"serialization - headers: {headers}")
    header_lines = []
    if "X-Forwarded-For" in headers:
        headers["X-Forwarded-For"].append(hostname)
    else:
        headers["X-Forwarded-For"] = peername
    logger.debug(f"Forwarded for: {headers['X-Forwarded-For']}")
    method = headers.pop("Method")
    path = headers.pop("Path")
    proto = headers.pop("Proto")
    header_lines.append(f"{method} {path} {proto}")
    for k, v in headers.items():
        header_lines.append(f"{k}: {v}")
    header_string = "\r\n".join(header_lines)
    header = header_string.encode()
    body = b""
    if body:
        content_type = headers["Content-Type"]
        if content_type == "application/json":
            body = json.dumps(body, ensure_ascii=False).encode()
        elif content_type == "text/html":
            body = body.encode()
    final = header + b"\r\n\r\n"
    if body:
        final += body
    logger.debug("Serialization done")
    return final


def serialize_resp(headers, reply_body):
    logger.debug("serizalizing response")
    # print(f"serialization - headers: {headers}")
    header_lines = []
    body = b""
    if reply_body:
        content_type = headers["Content-Type"]
        if "application/json" in content_type:
            body = json.dumps(
                reply_body, separators=(",", ":"), ensure_ascii=False
            ).encode()
            print(f"body: {body}")
        elif "text/html" in content_type:
            body = reply_body.encode()
    logger.debug(f" Headers: {headers}")
    headers["Content-Length"] = len(body)
    proto = headers.pop("Proto")
    code = headers.pop("Code")
    message = headers.pop("Message")
    header_lines.append(f"{proto} {code} {message}")
    for k, v in headers.items():
        header_lines.append(f"{k}:{v}")
    header_string = "\r\n".join(header_lines)
    header = header_string.encode()
    final = header + b"\r\n\r\n"
    logger.debug(body)
    if body:
        final += body
    logger.debug(f"Final message {final}")
    return final
    # self.c_outb += final
