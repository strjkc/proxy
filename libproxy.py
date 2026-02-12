import selectors, json, socket
import time
from connection_manager import C_Mag_Connection, C_Mag
import traceback


class Message:
    def __init__(self, socket, selector, addr, connection_manager):
        self.c_inb = b""
        self.c_outb = b""
        self.s_inb = b""
        self.s_outb = b""
        self.connection_manager = connection_manager
        self.selector = selector
        self.c_sock = socket
        self.c_idle_time = 10
        self.s_idle_time = 5
        self.c_last_activity = time.time()
        self.s_last_activity = time.time()
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

    def _parse_request(self, buffer):
        print("parsing request")
        delimiter = b"\r\n\r\n"
        if delimiter not in buffer:
            print("uuuu no delimiter in request :(")
            return
        headers = self.parse_req_headers()
        # do we have a body?
        body = ""
        if "Content-Length" in headers and "Content-Type" in headers:
            c_length = int(headers["Content-Length"])
            b_body = self.c_inb[:c_length]
            self.c_inb = self.c_inb[c_length:]
            body = self._parse_body(headers, b_body)
            print(f"body is : {body}")
        return headers, body

    def parse_req_headers(self):
        i = self.c_inb.index(b"\r\n\r\n")
        b_header = self.c_inb[:i]
        print(f"byte header: {b_header}")
        self.c_inb = self.c_inb[i + 4 :]
        print(f"resto of buffer: {self.c_inb}")
        return self._parse_request_headers(b_header)

    def _parse_response(self, buffer):
        delimiter = b"\r\n\r\n"
        if delimiter not in buffer:
            return
        headers = self._parse_resp_headers()
        body = ""
        if "Content-Length" in headers and "Content-Type" in headers:
            c_length = int(headers["Content-Length"])
            b_body = self.s_inb[:c_length]
            self.s_inb = self.s_inb[c_length:]
            print(f"b_body: {b_body}")
            body = self._parse_body(headers, b_body)
            print(f"body is : {body}")
        return headers, body

    def _parse_resp_headers(self):
        i = self.s_inb.index(b"\r\n\r\n")
        print("Buffer pefore searching for the delimiter:\n")
        print(self.s_inb)
        print("")
        b_header = self.s_inb[:i]
        print(f"byte header:\n\n{b_header}")
        self.s_inb = self.s_inb[i + 4 :]
        print(f"resto of buffer: {self.s_inb}")
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
        print(f_arr)
        if len(f_arr) != 3:
            raise ValueError("Invalid headers")
        proto, code, message = self._validate_response_headers(f_arr)
        parsed["proto"] = proto
        parsed["code"] = code
        parsed["message"] = message
        for header in arr:
            k, v = header.split(": ")
            parsed[k] = v
        return parsed

    def _parse_request_headers(self, headers):
        print("parsing headers")
        parsed = {}
        h_string = headers.decode()
        first_line, *arr = h_string.split("\r\n")
        print(f"first line: {first_line}")
        print(f"rest: {arr}")
        f_arr = first_line.split(" ")
        if len(f_arr) != 3:
            raise ValueError("Invalid headers")
        method, path, protocol = self._validate_headers(f_arr)
        parsed["method"] = method
        parsed["path"] = path
        parsed["proto"] = protocol
        for header in arr:
            k, v = header.split(": ")
            parsed[k] = v
        return parsed

    def _parse_body(self, headers, body):
        if "Content-Length" not in headers:
            # we will ignore the body if there is no Content-Length but we must forward only if the header GET
            return
        if "Content-Type" not in headers:
            return
        content_len = int(headers["Content-Length"])
        content_type = headers["Content-Type"]
        print(f"content type: {content_type}")
        if len(body) != content_len:
            raise ValueError("Content length missmatch")

        if "application/json" in content_type:
            b = body.decode()
            print(f"This should be body as string: \n {type(b)}")
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
        print(method, path, protocol)
        if method not in self.valid_methods:
            raise ValueError("Invalid HTTP Method Used")
        if protocol != "HTTP/1.1":
            raise ValueError("Invalid Protocol")
        return method, path, protocol

    def _serialize_req(self):
        print("serializing request")
        header_lines = []
        # adding new headers
        # set the route
        if "X-Forwarded-For" in self.req_headers:
            self.req_headers["X-Forwarded-For"].append(self.c_sock.gethostname())
        else:
            hosts = self.c_sock.getpeername()[0]
            self.req_headers["X-Forwarded-For"] = hosts
        print(f"Forwarded for: {self.req_headers['X-Forwarded-For']}")
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
        print("Serialization done")

    def _serialize_resp(self):
        print("serizalizing response")
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
        print(f" Headers: {self.reply_headers}")
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
        print(body)
        if body:
            final += body
        print(f"Final message {final}")
        self.c_outb += final

    def _forward_to_server(self):
        print("forwarding to server")
        ip, port = self.server_addr.split(":")
        self.s_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_sock.connect((ip, int(port)))
        print(f"ip: {ip} port: {port}")
        print("connected")
        self.s_sock.setblocking(False)
        # self.s_sock.setblocking(False)
        print(self.s_outb)
        self.s_sock.sendall(self.s_outb)
        self.connection_manager.add_connection(
            C_Mag_Connection(self.s_sock, self.s_idle_time, time.time())
        )
        print("sent all")
        # self.s_last_activity = time.time()
        self.selector.register(self.s_sock, selectors.EVENT_READ, data=self)
        self.sent_to_server = True

    def _receive_request(self):
        data = self.c_sock.recv(4096)
        if data:
            self.connection_manager.add_connection(
                C_Mag_Connection(self.c_sock, self.c_idle_time, time.time())
            )
            print("populating c_in buffer")
            self.c_inb += data
            self.req_headers, self.req_body = self._parse_request(self.c_inb)
            print(f"request headers: {self.req_headers} request body:{self.req_body}")
            self.request_ready = True
        else:
            # print("There is nothing to do here")
            return
            # print("Client sent EOF, closing connection")
            # self.selector.unregister(self.c_sock)
            # self.c_sock.close()

    def _receive_reply(self):
        data = self.s_sock.recv(4096)
        if data:
            print(f"reading data {data}")
            self.s_inb += data
            self.connection_manager.modify_last_act_time(self.s_sock, time.time())
            self.reply_headers, self.reply_body = self._parse_response(self.s_inb)
            self.response_ready = True
            self.s_last_activity = time.time()
            print(
                f"Done parsing reply:\n Header: {self.reply_headers}\n Body: {self.reply_body}"
            )
        else:
            print("Server in buffer empty, nothing to do here")
            return

    def _send_reply(self):
        print("sending reply")
        if not self.reply_body:
            return
        self.c_sock.sendall(self.c_outb)
        self.connection_manager.modify_last_act_time(self.s_sock, time.time())
        self.response_ready = False
        self.sent_to_server = False
        print(f"Sending data: {self.c_outb}")

    def handle_connection(self, event):
        try:
            if event & selectors.EVENT_READ and not self.sent_to_server:
                self._receive_request()
                if self.request_ready:
                    print("Body is parsed")
                    self._serialize_req()
                    self._forward_to_server()
                    self.request_ready = False
                    self.c_last_activity = time.time()
                    #        else:
                    # jc_idle_time = time.time() - self.c_last_activity
                    # s_idle_time = time.time() - self.s_last_activity
                    # if c_idle_time >= self.c_idle_time:
                    #    print("Connection idle for too long, closing socket")
                    #    self.selector.unregister(self.c_sock)
                    #    self.c_sock.close()
                    # if s_idle_time >= self.s_idle_time:
                    #     self.selector.unregister(self.s_sock)
                    #     self.s_sock.close()
            elif event & selectors.EVENT_READ and self.sent_to_server:
                print("Receiving reply")
                self._receive_reply()
                print(f"this should be an alive socket {self.c_sock}")
                self.selector.modify(self.c_sock, selectors.EVENT_WRITE, data=self)
                print("done receiving reply")
            elif event & selectors.EVENT_WRITE and self.response_ready:
                print("Event for sending reply to client")
                self._serialize_resp()
                self._send_reply()
                self.selector.modify(self.c_sock, selectors.EVENT_READ, data=self)
                print("done sending")
                self.c_last_activity = time.time()
        except Exception as e:
            print(f"Something went wrong yo: {e}")
            traceback.print_exc()
            self.selector.unregister(self.c_sock)
            self.c_sock.close()
            if self.s_sock:
                self.selector.unregister(self.s_sock)
                self.s_sock.close()

    def _init(self):
        self.c_outb = b""
        self.c_inb = b""
        self.s_inb = b""
        self.s_outb = b""
        self.req_headers = {}
        self.req_body = None
        self.reply_body = None
        self.reply_headers = {}


# connection is accepted
# parse message - i don't need to - i can just forward for now
# serialize message
# open connection to server
# accept reply from server
# parse message
# add proxy signature
# send to client
