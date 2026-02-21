import logging
import uuid
import bisect
import selectors
import json
import socket
import time
from connection_manager import C_Mag_Connection, C_Mag
import traceback

logger = logging.getLogger(__name__)


class Message:
    def __init__(
        self,
        socket,
        selector,
        addr,
        connection_manager,
        route_map,
        upstream_status,
        buckets,
    ):
        self.c_inb = b""
        self.c_outb = b""
        self.s_inb = b""
        self.s_outb = b""
        self.req_uuid = None
        self.connection_manager = connection_manager
        self.selector = selector
        self.c_sock = socket
        self.c_idle_time = 2
        self.s_idle_time = 2
        self.c_last_activity = 0
        self.s_last_activity = 0
        self.s_sock = None
        self.req_headers = {}
        self.req_body = None
        self.reply_headers = {}
        self.reply_body = None
        # I'm not gonna allow all http methods because f*** you
        self.valid_methods = ["GET", "POST", "PUT", "PATCH"]
        self.server_addr = addr
        self.sent_to_server = False
        self.response_ready = False
        self.request_ready = False
        self.req_started_at = None
        self.reply_started_at = None
        self.max_header_len = 32 * 1024
        self.route_map = route_map
        self.addr_for_route = ""
        self.upstream_status = upstream_status
        self.req_received_at = 0
        self.resp_sent_at = 0
        self.buckets = buckets

    def _send_metrics(self):
        b_buckets = json.dumps(self.buckets, ensure_ascii=False).encode()
        length = len(b_buckets)
        resp = (
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
            + str(length)
            + "\r\n\r\n"
        )
        data = resp.encode() + b_buckets
        self.c_sock.send(data)

    def _send_timeout_reply(self):
        data = b"HTTP/1.1 408 Request Timeout\r\nConection: close\r\n\r\n"
        self.c_sock.sendall(data)

    def _send_server_timeout(self):
        data = b"HTTP/1.1 504 Gateway Timeout\r\nConection: close\r\n\r\n"
        self.c_sock.sendall(data)

    def _send_upstream_unavailable(self):
        data = b"HTTP/1.1 503 Service Unavailable\r\nConection: close\r\n\r\n"
        self.c_sock.sendall(data)

    def _send_long_headers(self):
        data = (
            b"HTTP/1.1 431 Request Header Fields Too Large\r\nConection: close\r\n\r\n"
        )
        self.c_sock.sendall(data)

    def _send_route_not_found(self):
        data = b"HTTP/1.1 404 Not Found\r\nConection: close\r\n\r\n"
        self.c_sock.sendall(data)

    def _parse_request(self, buffer):
        logger.debug("parsing request")
        delimiter = b"\r\n\r\n"
        if delimiter not in buffer:
            if len(buffer) > self.max_header_len:
                self._send_long_headers()
            logger.debug("uuuu no delimiter in request :(")
            return
        if not self.req_headers:
            self.req_headers = self.parse_req_message()
        body = ""
        if "Content-Length" in self.req_headers:
            c_length = int(self.req_headers["Content-Length"])
            if len(self.c_inb) < c_length:
                self.req_body = None
                return
            # do we have a body?
            if "content-type" in self.req_headers:
                c_length = int(self.req_headers["Content-Length"])
                b_body = self.c_inb[:c_length]
                self.c_inb = self.c_inb[c_length:]
                body = self._parse_body(self.req_headers, b_body)
                logger.debug(f"body is : {body}")
        self.req_body = body

    def parse_req_message(self):
        i = self.c_inb.index(b"\r\n\r\n")
        b_header = self.c_inb[:i]
        logger.debug(f"byte header: {b_header}")
        self.c_inb = self.c_inb[i + 4 :]
        logger.debug(f"resto of buffer: {self.c_inb}")
        return self._parse_request_headers(b_header)

    def _parse_response(self, buffer):
        delimiter = b"\r\n\r\n"
        if delimiter not in buffer:
            if len(buffer) > self.max_header_len:
                logger.debug(
                    f"Upstream sent headers taht exceed {self.max_header_len}, connection closed"
                )
                self.selector.unregister(self.s_sock)
                self.s_sock.close()
                self._send_server_timeout()
            return
        if not self.reply_headers:
            self.reply_headers = self._parse_resp_headers()
        body = ""
        if "Content-Length" in self.reply_headers:
            if len(self.s_inb) < int(self.reply_headers["Content-Length"]):
                self.reply_body = None
                return
            if "Content-Type" in self.reply_headers:
                c_length = int(self.reply_headers["Content-Length"])
                b_body = self.s_inb[:c_length]
                self.s_inb = self.s_inb[c_length:]
                logger.debug(f"b_body: {b_body}")
                body = self._parse_body(self.reply_headers, b_body)
                logger.debug(f"body is : {body}")
        self.reply_body = body

    def _parse_resp_headers(self):
        i = self.s_inb.index(b"\r\n\r\n")
        logger.debug("Buffer pefore searching for the delimiter:\n")
        logger.debug(self.s_inb)
        logger.debug("")
        b_header = self.s_inb[:i]
        logger.debug(f"byte header:\n\n{b_header}")
        self.s_inb = self.s_inb[i + 4 :]
        logger.debug(f"resto of buffer: {self.s_inb}")
        return self._parse_response_headers(b_header)

    def _parse_response_headers(self, headers):
        parsed = {}
        h_string = headers.decode()
        first_line, *arr = h_string.split("\r\n")
        f_arr = first_line.split(" ")
        if len(f_arr) > 3:
            rest = " ".join(f_arr[2:])
            f_arr = f_arr[:2]
            f_arr.append(rest)
        logger.debug(f_arr)
        if len(f_arr) != 3:
            raise ValueError("Invalid headers")
        proto, code, message = self._validate_response_headers(f_arr)
        parsed["proto"] = proto
        parsed["code"] = code
        parsed["message"] = message
        for header in arr:
            k, v = header.split(": ")
            k = self._normalize_header_key(k)
            parsed[k] = v
        return parsed

    def _parse_request_headers(self, headers) -> dict:
        logger.debug("parsing headers")
        parsed = {}
        h_string = headers.decode()
        first_line, *arr = h_string.split("\r\n")
        logger.debug(f"first line: {first_line}")
        logger.debug(f"rest: {arr}")
        f_arr = first_line.split(" ")
        if len(f_arr) != 3:
            raise ValueError("Invalid headers")
        method, path, protocol = self._validate_headers(f_arr)
        parsed["method"] = method
        parsed["path"] = path
        parsed["proto"] = protocol
        for header in arr:
            k, v = header.split(": ")
            k = self._normalize_header_key(k)
            parsed[k] = v
        return parsed

    def _normalize_header_key(self, key):
        f = key.lower()
        if "-" in f:
            return "-".join([part.capitalize() for part in f.split("-")])
        return f.capitalize()

    def _parse_body(self, headers, body):
        if "Content-Length" not in headers:
            # we will ignore the body if there is no Content-Length but we must forward only if the header GET
            return
        if "Content-Type" not in headers:
            return
        content_len = int(headers["Content-Length"])
        content_type = headers["Content-Type"]
        logger.debug(f"content type: {content_type}")
        if len(body) != content_len:
            raise ValueError("Content length missmatch")

        if "application/json" in content_type:
            b = body.decode()
            logger.debug(f"This should be body as string: \n {type(b)}")
            return json.loads(b)
        elif "text/html" in content_type:
            return body.decode()
        raise ValueError("Invalid body content type")

    def _validate_response_headers(self, headers_arr):
        proto, code, message = headers_arr
        if proto != "HTTP/1.1":
            raise ValueError("Invalid Protocol")
        return proto, code, message

    def _validate_headers(self, headers_arr):
        method, path, protocol = headers_arr
        logger.debug(method, path, protocol)
        if method not in self.valid_methods:
            raise ValueError("Invalid HTTP Method Used")
        if protocol != "HTTP/1.1":
            raise ValueError("Invalid Protocol")
        return method, path, protocol

    def _serialize_req(self):
        logger.debug("serializing request")
        header_lines = []
        # adding new headers
        # set the route
        if "X-Forwarded-For" in self.req_headers:
            self.req_headers["X-Forwarded-For"].append(self.c_sock.gethostname())
        else:
            hosts = self.c_sock.getpeername()[0]
            self.req_headers["X-Forwarded-For"] = hosts
        logger.debug(f"Forwarded for: {self.req_headers['X-Forwarded-For']}")
        ###
        method = self.req_headers.pop("method")
        path = self.req_headers.pop("path")
        proto = self.req_headers.pop("proto")
        header_lines.append(f"{method} {path} {proto}")
        for k, v in self.req_headers.items():
            header_lines.append(f"{k}: {v}")
        header_string = "\r\n".join(header_lines)
        header = header_string.encode()
        body = b""
        if self.req_body:
            content_type = self.req_headers["Content-Type"]
            if content_type == "application/json":
                body = json.dumps(self.req_body, ensure_ascii=False).encode()
            elif content_type == "text/html":
                body = self.req_body.encode()

        final = header
        if body:
            final += b"\r\n\r\n" + body
        self.s_outb += final + b"\r\n\r\n"
        logger.debug("Serialization done")

    def _serialize_resp(self):
        logger.debug("serizalizing response")
        header_lines = []
        body = b""
        if self.reply_body:
            content_type = self.reply_headers["Content-Type"]
            if "application/json" in content_type:
                # self.reply_body["proxy"] = "signed"
                body = json.dumps(self.reply_body, ensure_ascii=False).encode()
            elif "text/html" in content_type:
                body = self.reply_body.encode()
                # body += b"<p>Proxy signed</p>"
        logger.debug(f" Headers: {self.reply_headers}")
        self.reply_headers["Content-Length"] = len(body)
        proto = self.reply_headers.pop("proto")
        code = self.reply_headers.pop("code")
        message = self.reply_headers.pop("message")
        header_lines.append(f"{proto} {code} {message}")
        for k, v in self.reply_headers.items():
            header_lines.append(f"{k}: {v}")
        header_string = "\r\n".join(header_lines)
        header = header_string.encode()
        final = header + b"\r\n\r\n"
        logger.debug(body)
        if body:
            final += body
        logger.debug(f"Final message {final}")
        self.c_outb += final

    def _forward_to_server(self):
        logger.debug("forwarding to server")
        # ip, port = self.server_addr.split(":")
        self.s_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self.s_sock.connect((ip, int(port)))
        self.s_sock.connect(self.addr_for_route)
        # logger.debug(f"ip: {ip} port: {port}")
        logger.debug("connected")
        self.s_sock.setblocking(False)
        # self.s_sock.setblocking(False)
        logger.debug(self.s_outb)
        self.s_sock.sendall(self.s_outb)
        if not self.connection_manager.obj_exists(self.s_sock):
            self.connection_manager.add_connection(
                C_Mag_Connection(self.s_sock, self.s_idle_time, time.time())
            )
        else:
            self.connection_manager.modify_last_act_time(self.s_sock, time.time())
        logger.debug("sent all")
        # self.s_last_activity = time.time()
        self.selector.register(self.s_sock, selectors.EVENT_READ, data=self)
        self.sent_to_server = True

    def _receive_request(self):
        if not self.connection_manager.obj_exists(self.c_sock):
            self.connection_manager.add_connection(
                C_Mag_Connection(self.c_sock, self.c_idle_time, time.time())
            )
        else:
            self.connection_manager.modify_last_act_time(self.c_sock, time.time())
        logger.info("Receiving request from client")
        data = self.c_sock.recv(4096)
        logger.info(f"Data read from socket buffer: {data}")
        if data:
            if not self.req_started_at:
                self.req_started_at = time.time()
            elapsed = time.time() - self.req_started_at
            if elapsed >= 6:
                self._send_timeout_reply()
                self.selector.unregister(self.c_sock)
                self.c_sock.close()
            # start the timer - if headers don't arrive in time terminate connection.
            # self.connection_manager.add_connection(
            # C_Mag_Connection(self.c_sock, self.c_idle_time, time.time())
            # )
            logger.debug("populating c_in buffer")
            self.c_inb += data
            logger.info(f"State of Client In Buffer: {self.c_inb}")
            self._parse_request(self.c_inb)
            if self.req_headers is None or self.req_body is None:
                # we keep buffering
                return
            # logger.debug(f"request headers: {self.req_headers} request body:{self.req_body}")
            self.request_ready = True
            self.req_started_at = None
        else:
            # logger.debug("There is nothing to do here")
            return
            # logger.debug("Client sent EOF, closing connection")
            # self.selector.unregister(self.c_sock)
            # self.c_sock.close()

    def _receive_reply(self):
        self.connection_manager.modify_last_act_time(self.s_sock, time.time())
        logger.info("Receiving reply from server")
        data = self.s_sock.recv(4096)
        logger.info(f"Data read from socket buffer {data}")
        if data:
            if not self.reply_started_at:
                self.reply_started_at = time.time()
            elapsed = time.time() - self.reply_started_at
            if elapsed >= 12:
                self.selector.unregister(self.s_sock)
                self.s_sock.close()
                self._send_server_timeout()
            logger.debug(f"reading data {data}")
            self.s_inb += data
            logger.info(f"State of Server In Buffer {self.s_inb}")
            self.connection_manager.modify_last_act_time(self.s_sock, time.time())
            self._parse_response(self.s_inb)
            if self.reply_body is None:
                return
            self.response_ready = True
            self.s_last_activity = time.time()
            logger.debug(
                f"Done parsing reply:\n Header: {self.reply_headers}\n Body: {self.reply_body}"
            )
        else:
            logger.debug("Server in buffer empty, nothing to do here")
            return

    def _send_reply(self):
        logger.debug("sending reply")
        if not self.reply_body:
            return
        self.c_sock.sendall(self.c_outb)
        self.connection_manager.modify_last_act_time(self.c_sock, time.time())
        self.response_ready = False
        self.sent_to_server = False
        logger.debug(f"Sending data: {self.c_outb}")

    def handle_connection(self, event):
        try:
            if event & selectors.EVENT_READ and not self.sent_to_server:
                self._receive_request()
                if self.request_ready:
                    self.request_received_at = time.time()
                    self.req_uuid = uuid.uuid4()
                    logger.info(f"Request with id: {self.req_uuid} starting")
                    logger.debug("Body is parsed")
                    logger.info(
                        f"""Request Headers:\n {self.req_headers}\nRequest body:\n{self.req_body}"""
                    )
                    logger.debug(
                        f"headers in request:{self.req_headers} body in request:{self.req_body}"
                    )
                    path = self.req_headers.get("path", None)
                    if path == "/pmetrics":
                        self._send_metrics()
                        return
                    logger.debug(f"path: {path}")
                    self.addr_for_route = self.route_map.get(path, None)
                    logger.info(
                        f"For route: {path} the address is: {self.addr_for_route}"
                    )
                    logger.debug(
                        f"For route: {path} the address is: {self.addr_for_route}"
                    )
                    if not self.addr_for_route:
                        self._send_route_not_found()
                        return
                    logger.debug(f"addr found for route: {self.addr_for_route}")
                    logger.debug(
                        f"upstream obj in request: {self.upstream_status[self.addr_for_route]}"
                    )
                    status = self.upstream_status[self.addr_for_route].status
                    logger.debug(f"status: {status}")
                    if not status:
                        logger.debug(
                            "Upstream is not healthy! Sending response to client"
                        )
                        self._send_upstream_unavailable()
                        return
                    self._serialize_req()
                    self._forward_to_server()
                    time.sleep(0.3)
                    logger.debug(
                        f"This is the upstream object: {self.upstream_status[self.addr_for_route]}"
                    )
                    self.upstream_status[self.addr_for_route].status = True
                    self.upstream_status[self.addr_for_route].checked = time.time()
                    self.request_ready = False
                    self.c_last_activity = time.time()
            elif event & selectors.EVENT_READ and self.sent_to_server:
                logger.debug("Receiving reply")
                self._receive_reply()
                logger.info(
                    f"""Reply Headers: {self.reply_headers}\nReply Body: {self.reply_body}"""
                )
                self.upstream_status[self.addr_for_route].status = True
                self.upstream_status[self.addr_for_route].checked = time.time()
                self.selector.modify(self.c_sock, selectors.EVENT_WRITE, data=self)
                logger.debug("done receiving reply")
            elif event & selectors.EVENT_WRITE and self.response_ready:
                logger.debug("Event for sending reply to client")
                self._serialize_resp()
                self._send_reply()
                self.reply_sent_at = time.time()
                logger.info(f"Latency: {self.reply_sent_at - self.request_received_at}")
                lat = self.reply_sent_at - self.request_received_at
                logger.debug(f"Lat: {lat}")
                self._populate_bucket(lat)
                self.selector.modify(self.c_sock, selectors.EVENT_READ, data=self)
                logger.info(f"Buckets: {self.buckets}")
                logger.debug("done sending")
                logger.info(f"Request with id: {self.req_uuid} ending")
                self._init()
                self.c_last_activity = time.time()
        except Exception as e:
            logger.debug(f"Something went wrong yo: {e}")
            traceback.print_exc()
            self.selector.unregister(self.c_sock)
            self.c_sock.close()
            if self.s_sock:
                self.selector.unregister(self.s_sock)
                self.s_sock.close()

    def _populate_bucket(self, latency):
        index = bisect.bisect_left(list(self.buckets.keys()), latency)
        self.buckets[list(self.buckets.keys())[index]] += 1

    def _init(self):
        self.c_inb = b""
        self.c_outb = b""
        self.s_inb = b""
        self.s_outb = b""
        self.req_uuid = None
        self.c_last_activity = 0
        self.s_last_activity = 0
        self.s_sock = None
        self.req_headers = {}
        self.req_body = None
        self.reply_headers = {}
        self.reply_body = None
        self.sent_to_server = False
        self.response_ready = False
        self.request_ready = False
        self.req_started_at = None
        self.reply_started_at = None
        self.addr_for_route = ""
