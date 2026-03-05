import time
import socket
import types
import selectors


class Health_Check:
    def __init__(self, upstream_status, selector):
        self.upstream_status = upstream_status
        self.connections = {}
        self.selector = selector
        self.check_interval = 5
        self.conn_timeout = 3

    def reap(self):
        for k, v in self.upstream_status.items():
            if not v.status and k in self.connections:
                last_actv = self.connections[k]["last_active"]
                curr_time = time.time()
                if curr_time - last_actv >= self.conn_timeout:
                    try:
                        sock = self.connections[k]["socket"]
                        self.selector.unregister(sock)
                        sock.close()
                    except Exception as e:
                        print(e)
                    finally:
                        if k in self.connections:
                            del self.connections[k]

    def open_connections(self):
        for addr in self.upstream_status:
            try:
                if addr not in self.connections:
                    sock, data = self._open_connection(addr)
                    self.connections[addr] = {
                        "socket": sock,
                        "data": data,
                        "check_sent": False,
                        "last_active": time.time(),
                    }
                self._prepare_and_send_hc(addr)
            except Exception as e:
                self.upstream_status[addr].status = False
                self.upstream_status[addr].checked = time.time()

    def _prepare_and_send_hc(self, addr):
        sock = self.connections[addr]["socket"]
        data = self.connections[addr]["data"]
        last_checked = self.upstream_status[addr].checked
        check_sent = self.connections[addr]["check_sent"]
        if time.time() - last_checked >= self.check_interval and not check_sent:
            self._send_health_check(sock, addr, data)

    def _send_health_check(self, sock, addr, key_data):
        msg = b"HEAD /health HTTP/1.1\r\nHost:127.0.0.1\r\n\r\n"
        try:
            sock.sendall(msg)
            self.selector.modify(sock, selectors.EVENT_READ, data=key_data)
            self.connections[addr]["check_sent"] = True
            self.connections[addr]["last_active"] = time.time()
        except Exception as e:
            self.upstream_status[addr].status = False
            self.upstream_status[addr].checked = time.time()
            print(e)

    def _recv_health_status(self, key):
        sock = key.fileobj
        conn_data = key.data
        data = sock.recv(4096)
        if data:
            conn_data.inb += data
            if b"\r\n\r\n" in conn_data.inb:
                status = b"200" in conn_data.inb
                self.upstream_status[conn_data.addr].status = status
                self.upstream_status[conn_data.addr].checked = time.time()
                self.selector.modify(sock, selectors.EVENT_WRITE, data=conn_data)
                self.connections[conn_data.addr]["check_sent"] = False
                self.connections[conn_data.addr]["last_active"] = time.time()
        else:
            self.upstream_status[conn_data.addr].status = False
            self.upstream_status[conn_data.addr].checked = time.time()

    def _open_connection(self, addr):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data = types.SimpleNamespace(addr=addr, inb=b"")
        sock.connect(addr)
        sock.setblocking(False)
        self.selector.register(sock, selectors.EVENT_WRITE, data=data)
        return sock, data

    def handle_connections(self, key, mask):
        if mask & selectors.EVENT_READ:
            addr = key.data.addr
            if addr in self.connections and "socket" in self.connections[addr]:
                sock = self.connections[addr]["socket"]
                if sock is key.fileobj:
                    self._recv_health_status(key)
