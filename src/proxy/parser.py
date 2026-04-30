import logging
import json
from os import stat

logger = logging.getLogger(__name__)


class Parser:
    def __init__(self):
        pass

    @staticmethod
    def __decode(buff: bytes) -> tuple[list[str], list[str]]:
        h_string = buff.decode()
        first_line, *arr = h_string.split("\r\n")
        logger.debug(f"first line: {first_line}")
        logger.debug(f"rest: {arr}")
        f_arr = first_line.split(" ")
        #if len(f_arr) != 3:
        #    raise ValueError("Invalid Request Line")
        return f_arr, arr

    @classmethod
    def __parse_headers(cls, headers: list[str]) -> dict:
        parsed = {}
        for header in headers:
            if header:
                k, v = header.split(":", 1)
                k = cls.__normalize_header_key(k)
                parsed[k] = v.strip()
        return parsed

    @staticmethod
    def __parse_req_line(headers: list[str]) -> dict:
        # _validate_request_headers(f_arr, valid_methods)
        method, path, protocol = headers
        parsed = {}
        parsed["Method"] = method.upper()
        parsed["Path"] = path
        parsed["Proto"] = protocol.upper()
        return parsed

    @staticmethod
    def __parse_stat_line(stat_line: list[str]) -> dict:
        if len(stat_line) > 3:
            rest = " ".join(stat_line[2:])
            stat_line = stat_line[:2]
            stat_line.append(rest)
        logger.debug(stat_line)
        if len(stat_line) != 3:
            raise ValueError("Invalid Status Line")
        parsed = {}
        # _validate_response_headers(
        proto, code, message = stat_line
        parsed["Proto"] = proto
        parsed["Code"] = code
        parsed["Message"] = message
        return parsed

    @classmethod
    def parse_request_headers(cls, headers: bytes, valid_methods: list) -> dict:
        logger.debug("parsing headers")
        if not headers:
            raise ValueError("Header bytes empty")
        try:
            f_arr, arr = cls.__decode(headers)
            parsed_req_line = cls.__parse_req_line(f_arr)
            cls.__validate_req_line(parsed_req_line, valid_methods)
            parsed_headers = cls.__parse_headers(arr)
            return {**parsed_req_line, **parsed_headers}
        except Exception as e:
            logger.exception(e)
            raise e

    @classmethod
    def parse_response_headers(cls, headers: bytes) -> dict:
        if not headers:
            raise ValueError("Header bytes empty")
        try:
            f_arr, arr = cls.__decode(headers)
            parsed_req_line = cls.__parse_stat_line(f_arr)
            cls.__validate_stat_line(parsed_req_line)
            parsed_headers = cls.__parse_headers(arr)
            return {**parsed_req_line, **parsed_headers}
        except Exception as e:
            logger.exception(e)
            raise e

    @staticmethod
    def __normalize_header_key(key):
        f = key.lower()
        if "-" in f:
            return "-".join([part.capitalize() for part in f.split("-")])
        return f.capitalize()

    @classmethod
    def parse_body(cls, body: bytes, content_type: str):
        logger.debug(f"content type: {content_type}")
        # print(f"parsing body of len: {len(body)}")
        if "application/json" in content_type:
            b = body.decode()
            logger.debug(f"This should be body as string: \n {type(b)}")
            return json.loads(b)
        elif "text/html" in content_type:
            return body.decode()
        raise ValueError("Invalid body content type")

    @staticmethod
    def __validate_stat_line(headers_arr):
        proto, code, message = headers_arr.values()
        if proto != "HTTP/1.1":
            raise ValueError("Invalid Protocol")
        return proto, code, message

    @staticmethod
    def __validate_req_line(headers:dict, valid_methods:list):
        method, path, protocol = headers.values()
        logger.debug(method, path, protocol)
        if method not in valid_methods:
            raise ValueError("Invalid HTTP Method Used")
        if protocol != "HTTP/1.1":
            raise ValueError("Invalid Protocol")
        if "/" not in path:
            raise ValueError("Invalid Path Format")

    @classmethod
    def serialize_req(cls, headers: dict, body: bytes | None = None):
        logger.debug("serializing request")
        header_lines = []
        method = headers.pop("Method")
        path = headers.pop("Path")
        proto = headers.pop("Proto")
        header_lines.append(f"{method} {path} {proto}")
        for k, v in headers.items():
            header_lines.append(f"{k}: {v}")
        header_string = "\r\n".join(header_lines)
        header = header_string.encode()
        final = header + b"\r\n\r\n"
        if body:
            final += body
        logger.debug("Serialization done")
        return final

    @classmethod
    def serialize_resp(cls, headers: dict, body: bytes | None):
        logger.debug("serizalizing response")
        header_lines = []
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
