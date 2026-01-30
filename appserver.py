import struct
import selectors
import json
import io


class Message:
    def __init__(self, sock, selector, address):
        self.socket = sock
        self.selector = selector
        self.address = address
        self.inbuffer = b""
        self.outbuffer = b""
        self.json_header_len = 0
        self.json_header = {}
        self.proto_header_len = 2
        self.body = ""
        self.response_created = False

    def _parse_proto_header(self):
        print("parsing proto header")
        if len(self.inbuffer) >= self.proto_header_len:
            self.json_header_len = struct.unpack(
                ">H", self.inbuffer[: self.proto_header_len]
            )[0]
            self.inbuffer = self.inbuffer[self.proto_header_len :]
        print(f"json header len: {self.json_header}")
        # error?

    def parse_json_header(self):
        print("parsing json header")
        if self.json_header_len == 0:
            self._parse_proto_header()
        if len(self.inbuffer) >= self.json_header_len:
            self.json_header = self.json_decode(
                self.inbuffer[: self.json_header_len], "utf-8"
            )
            self.inbuffer = self.inbuffer[self.json_header_len :]
            for mandatory_header in (
                "byteorder",
                "content-length",
                "content-type",
                "content-encoding",
            ):
                if mandatory_header not in self.json_header:
                    raise ValueError(f"Missing required header {mandatory_header}")
            print(f"json header {self.json_header}")

    def parse_content(self):
        print("Parsing content")
        if not self.json_header:
            self.parse_json_header()
        content_len = self.json_header["content-length"]
        encoding = self.json_header["content-encoding"]
        cont_type = self.json_header["content-type"]
        if len(self.inbuffer) >= content_len:
            content_bytes = self.inbuffer[:content_len]
            if cont_type != "text/json":
                # I'm gonna sent a response here for invalid content
                pass
            self.body = self.json_decode(content_bytes, encoding)
            self.inbuffer = self.inbuffer[content_len:]
            print(f"Parsed received content: {self.json_header} body:{self.body}")

    def json_decode(self, bytes, encoding):
        print("decoding json")
        tiow = io.TextIOWrapper(io.BytesIO(bytes), encoding, newline="")
        try:
            obj = json.load(tiow)
        except Exception as e:
            print("returning as string")
            # TODO this is a hack because i want to receive plain text and json in the body
            return tiow.read()
        tiow.close()
        print("returning as json")
        return obj

    def serialize_content(self):
        print("Creating message")
        encoding = self.json_header["content-encoding"]
        print(f"Encoding: {encoding}")
        content_bytes = json.dumps(self.body).encode(encoding)
        print(f"Content: {content_bytes}")
        header = {
            "byteorder": "little",
            "content-length": len(content_bytes),
            "content-encoding": encoding,
            "content-type": "text/json",
        }
        header_bytes = json.dumps(header).encode("utf-8")
        print(f"Header {header_bytes}")
        proto_header = len(header_bytes)
        proto_header_bytes = struct.pack(">H", proto_header)
        print(f"Proto Header {proto_header_bytes}")
        self.outbuffer += proto_header_bytes
        self.outbuffer += header_bytes
        self.outbuffer += content_bytes
        print(f"populated out buffer: {self.outbuffer}")
        self.response_created = True

    def handle_event(self, event):
        if event & selectors.EVENT_READ:
            try:
                print("Handling event READ")
                data = self.socket.recv(1024)
                print(f"This is the data received: {data}")
                if data:
                    self.inbuffer += data
                    print(f"buffering data {self.inbuffer}")
                    print("Parsing content")
                    self.parse_content()
                elif data == b"":
                    self.selector.unregister(self.socket)
                    self.socket.close()
            except BlockingIOError:
                print("No data")
        elif event & selectors.EVENT_WRITE:
            print("Handling event WRITE")
            if not self.response_created and self.body:
                self.serialize_content()
            elif self.response_created:
                print(f"sending data {self.outbuffer}")
                sent = self.socket.send(self.outbuffer)
                self.outbuffer = self.outbuffer[sent:]
                print(f"Buffer state after sending: {self.outbuffer}")
                if not self.outbuffer:
                    print(f"Closing connection {self.address}")
                    self.response_created = False
                    self.selector.unregister(self.socket)
                    self.socket.close()
            # call the function serialize content to populate the output buffer
            # if the output buffer is not empty send data
            # track the data that was sent and restart from there in case not everything was sent
