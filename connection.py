import logging
import parser
import socket
import time

logger = logging.getLogger(__name__)


class Connection:
    def __init__(
        self,
        socket,
        idle_time: int,
        read_timeout: int,
    ):
        self.inb = bytearray()
        self.outb = bytearray()
        self.req_uuid = None
        self.socket = socket
        self.idle_time = idle_time
        self.read_timeout = read_timeout
        self.last_activity = 0
        self.headers = {}
        self.body = None
        self.valid_methods = ["GET", "POST", "PUT", "PATCH"]
        self.req_started_at = 0  # <-
        self.max_header_len = 8 * 1024  # <-
        self.header_delimiter = b"\r\n\r\n"

    # done
    def get_headers_from_buffer(self, buffer, max_header_len: int):
        if self.header_delimiter not in buffer:
            if len(buffer) > max_header_len:
                raise ValueError("Headers too long")
            return
        i = buffer.index(self.header_delimiter)
        header_b = bytes(buffer[:i])
        del buffer[: i + len(self.header_delimiter)]
        # print(f"After parsing headers this remains in the buffer {buffer}")
        return header_b

    def parse_request_headers(self):
        if not self.headers:
            header_b = self.get_headers_from_buffer(self.inb, self.max_header_len)
            logger.info(f"header bytes returned {header_b}")
            if not header_b:
                return
            self.headers = parser.parse_request_headers(header_b, self.valid_methods)
            logger.info(f"headers parsed {self.headers}")

    def parse_reply_headers(self):
        if not self.headers:
            header_b = self.get_headers_from_buffer(self.inb, self.max_header_len)
            logger.info(f"header bytes returned {header_b}")
            if not header_b:
                return
            self.headers = parser.parse_response_headers(header_b)
            logger.info(f"headers parsed {self.headers}")
            # print(f"In buffer after parsing headers: {self.inb}")

    # done
    def get_body_from_buffer(self, buffer, headers):
        if not headers:
            return
        body = ""
        if "Content-Length" in headers:
            c_length = int(headers["Content-Length"])
            if len(buffer) < c_length:
                return
            c_type = headers.get("Content-Type", "text/html")
            # print(f"buffer when starting to parse body: {buffer}")
            body_b = buffer[:c_length]
            del buffer[:c_length]
            # print(f"body b {body_b}")
            body = parser.parse_body(body_b, c_type)
            logger.debug(f"body is : {body}")
        self.body = body
        logger.info("parsed body")

    # to finish
    def _validate_haning_time(self, timeout_s: int, actv_callback):
        # print("checking hang time")
        if not self.req_started_at:
            self.req_started_at = time.time()
        elapsed = time.time() - self.req_started_at
        if elapsed >= timeout_s:
            # print("should be timed out")
            # a hack for now :)
            actv_callback(self, time.time() - 10000000)
            # report to manager with reason why he should unregister this socket from the selector, and close it

    # done, remove comments if everyghing works
    def receive_req(self, actv_callback) -> tuple:
        actv_callback(self, time.time())
        logger.info("Receiving request from client")
        # print("Receiving request from client")
        try:
            data = self.socket.recv(4096)
        except Exception as e:
            print(f"Error reading data: {e}")
            return None, None
        logger.info(f"Data read from socket buffer: {data}")
        if data:
            self._validate_haning_time(self.read_timeout, actv_callback)
            logger.debug("populating in buffer")
            self.inb.extend(data)
            logger.info(f"State of Client In Buffer: {self.inb}")
            self.parse_request_headers()
            self.get_body_from_buffer(self.inb, self.headers)
            if not self.headers or self.body is None:
                raise ValueError(
                    f"headers are falsy {self.headers} or body is none: {self.body}"
                )
            # print("returning header and body")
            headers, body = self._snapshot_state()
            self.headers = {}
            self.body = None
            return headers, body
        else:
            logger.debug("Trying to read data, but the socket buffer is empty")
            return None, None

    def receive_resp(self, actv_callback):
        actv_callback(self, time.time())
        logger.info("Receiving reply from server")
        try:
            data = self.socket.recv(4096)
        except Exception as e:
            print(f"Error reading data: {e}")
            return
        logger.info(f"Data read from socket buffer {data}")
        if data:
            self._validate_haning_time(self.read_timeout, actv_callback)
            logger.debug(f"reading data {data}")
            self.inb.extend(data)
            self.parse_reply_headers()
            # print("headers parsed")
            self.get_body_from_buffer(self.inb, self.headers)
            # print("body parsed")
            if not self.headers or self.body is None:
                raise ValueError(
                    f"headers are falsy {self.headers} or body is none: {self.body}"
                )
            headers, body = self._snapshot_state()
            self.headers = {}
            self.body = None
            return headers, body
        else:
            logger.debug("Server in buffer empty, nothing to do here")
            return

    def send_request(self, data, actv_callback):
        # todo get hostname and other sokcet stuff from manager
        # print(f"socket from sedn {self.socket}")
        # print(f"hostname from socket {socket.gethostbyname(socket.gethostname())}")
        data_b = parser.serialize_req(
            data.headers,
            data.body,
            socket.gethostbyname(socket.gethostname()),
            self.socket.getpeername()[0],
        )
        self.outb.extend(data_b)
        actv_callback(self, time.time())
        self._send_over_socket()
        return True

    def send_response(self, data, actv_callback):
        data_b = parser.serialize_resp(data.headers, data.body)
        self.outb.extend(data_b)
        actv_callback(self, time.time())
        self._send_over_socket()
        return True

    def _send_over_socket(self):
        logger.debug(f"Sending data: {self.outb}")
        sent = self.socket.send(self.outb)
        self.outb = self.outb[sent:]

    def _snapshot_state(self):
        headers = dict(self.headers)
        body = None
        if isinstance(self.body, dict):
            body = dict(self.body)
        elif isinstance(self.body, list):
            body = list(self.body)
        else:
            body = str(self.body)
        return headers, body
