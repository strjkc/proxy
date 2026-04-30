import logging
from proxy.parser import Parser
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
    def __get_headers_from_buffer(self, buffer, max_header_len: int):
        if self.header_delimiter not in buffer:
            if len(buffer) > max_header_len:
                raise ValueError("Headers too long")
            return
        i = buffer.index(self.header_delimiter)
        header_b = bytes(buffer[:i])
        del buffer[: i + len(self.header_delimiter)]
        return header_b

    def __parse_request_headers(self):
        if not self.headers:
            header_b = self.__get_headers_from_buffer(self.inb, self.max_header_len)
            logger.info(f"header bytes returned {header_b}")
            if not header_b:
                return
            self.headers = Parser.parse_request_headers(header_b, self.valid_methods)
            logger.info(f"headers parsed {self.headers}")

    def __parse_reply_headers(self):
        if not self.headers:
            header_b = self.__get_headers_from_buffer(self.inb, self.max_header_len)
            logger.info(f"header bytes returned {header_b}")
            if not header_b:
                return
            self.headers = Parser.parse_response_headers(header_b)
            logger.info(f"headers parsed {self.headers}")

    # done
    def __get_body_from_buffer(self, buffer, headers):
        if not headers:
            return
        body = ""
        if "Content-Length" in headers:
            c_length = int(headers["Content-Length"])
            if len(buffer) < c_length:
                return
            c_type = headers.get("Content-Type", "text/html")
            body_b = buffer[:c_length]
            del buffer[:c_length]
            body = Parser.parse_body(body_b, c_type)
            logger.debug(f"body is : {body}")
        self.body = body
        logger.info("parsed body")

    # to finish
    def _validate_haning_time(self, timeout_s: int, actv_callback):
        if not self.req_started_at:
            self.req_started_at = time.time()
        elapsed = time.time() - self.req_started_at
        if elapsed >= timeout_s:
            # a hack for now :)
            actv_callback(self, time.time() - 10000000)
            # report to manager with reason why he should unregister this socket from the selector, and close it

    def receive_req(self, actv_callback) -> tuple:
        actv_callback(self, time.time())
        logger.info("Receiving request from client")
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
            self.__parse_request_headers()
            self.__get_body_from_buffer(self.inb, self.headers)
            #headers are parsed?
            #should we expect a body?
            #if yes we need to set the state to parsing body - read the len from buffer based on content length
            #if no, return if yes raise an exception that we are still buffering for the body
            #body parsed? - just return
            if not self.headers or self.body is None:
                raise ValueError(
                    f"headers are falsy {self.headers} or body is none: {self.body}"
                )
            headers, body = self.__snapshot_state()
            self.headers = {}
            self.body = None
            self.req_started_at = 0
            return headers, body
        else:
            raise ValueError("No Data in Socket")
            logger.debug("Trying to read data, but the socket buffer is empty")

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
            self.__parse_reply_headers()
            self.__get_body_from_buffer(self.inb, self.headers)
            if not self.headers or self.body is None:
                raise ValueError(
                    f"headers are falsy {self.headers} or body is none: {self.body}"
                )
            headers, body = self.__snapshot_state()
            self.headers = {}
            self.body = None
            self.req_started_at = 0
            return headers, body
        else:
            logger.debug("Server in buffer empty, nothing to do here")
            return

    def send_request(self, data, actv_callback):
        if "X-Forwarded-For" in self.headers:
            self.headers["X-Forwarded-For"].append(
                socket.gethostbyname(socket.gethostname())
            )
        else:
            self.headers["X-Forwarded-For"] = self.socket.getpeername()[0]
        logger.debug(f"Forwarded for: {self.headers['X-Forwarded-For']}")

        data_b = Parser.serialize_req(
            data.headers,
            data.body,
        )
        self.outb.extend(data_b)
        actv_callback(self, time.time())
        self.__send_over_socket()
        return True

    def send_response(self, data, actv_callback):
        data_b = Parser.serialize_resp(data.headers, data.body)
        self.outb.extend(data_b)
        actv_callback(self, time.time())
        self.__send_over_socket()
        return True

    def __send_over_socket(self):
        logger.debug(f"Sending data: {self.outb}")
        sent = self.socket.send(self.outb)
        self.outb = self.outb[sent:]

    def __snapshot_state(self):
        headers = dict(self.headers)
        body = None
        if isinstance(self.body, dict):
            body = dict(self.body)
        elif isinstance(self.body, list):
            body = list(self.body)
        else:
            body = str(self.body)
        return headers, body
