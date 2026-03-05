import selectors
import bisect
import traceback
import socket
import types
import time
from connection import Connection
import set_responses as responses


class Connection_Manager:
    def __init__(
        self, selector, client_socket, upstream_status: dict, buckets: dict
    ) -> None:
        self.upstream_status = upstream_status
        self.selector = selector
        self.client_socket = client_socket
        self.server_socket = None
        self.client_connection = Connection(self.client_socket, 5, 5)
        self.server_connection = None
        self.request_data = types.SimpleNamespace(headers={}, body=None)
        self.response_data = types.SimpleNamespace(headers={}, body=None)
        self.connection_activity = {self.client_connection: time.time()}
        self.upstream_rutes = {
            "/app": ("127.0.0.1", 8080),
            "/app/": ("127.0.0.1", 8080),
            "/api/chirps": ("127.0.0.1", 8081),
            "/api/chirps/": ("127.0.0.1", 8081),
        }
        self.req_received_at = 0
        self.buckets = buckets

    def update_buckets(self, time):
        bukcet_keys = list(self.buckets.keys())
        index = bisect.bisect_left(bukcet_keys, time)
        self.buckets[bukcet_keys[index]] += 1

    def is_upstream_active(self, addr):
        if addr in self.upstream_status:
            return self.upstream_status[addr].status

    def set_req_data(self, headers, body):
        self.request_data.headers = headers
        self.request_data.body = body

    def set_resp_data(self, headers, body):
        self.response_data.headers = headers
        self.response_data.body = body

    def set_activity(self, obj, last_act_time):
        self.connection_activity[obj] = last_act_time

    def reap(self):
        keys = list(self.connection_activity.keys())
        for k in keys:
            curr_time = time.time()
            timeout_value = self.connection_activity[k]
            if curr_time - timeout_value >= k.idle_time:
                try:
                    print(f"removing socket due to inactivity {k.socket}")
                    self.selector.unregister(k.socket)
                    k.socket.close()
                except Exception as e:
                    print(f"Exception closing socket {e}")
                finally:
                    del self.connection_activity[k]

    def open_connection(self, addr):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.connect(addr)
        self.server_socket.setblocking(False)
        self.server_connection = Connection(self.server_socket, 10, 10)
        self.selector.register(self.server_socket, selectors.EVENT_WRITE, data=self)

    # open connection to server
    def handle_connections(self, key, event):
        fileobj = key.fileobj
        try:
            if event & selectors.EVENT_READ and fileobj is self.client_socket:
                if not self.client_connection:
                    self.client_connection = Connection(self.client_socket, 5, 5)
                print("receiving request")
                self.req_received_at = time.time()
                headers, body = self.client_connection.receive_req(self.set_activity)
                if headers is None and body is None:
                    print("eof read, closing connection")
                    self.selector.unregister(self.client_socket)
                    self.client_socket.close()
                    return
                # print("setting data")
                self.set_req_data(headers, body)
                if self.request_data.headers:
                    print("ready to send request")
                    h_path = self.request_data.headers["Path"]
                    if h_path == "/pmetrics":
                        headers = responses.get_metrics_data()
                        self.set_resp_data(headers, self.buckets)
                        self.selector.modify(
                            self.client_socket,
                            selectors.EVENT_WRITE,
                            data=self,
                        )
                        return
                    addr = self.upstream_rutes.get(h_path, None)
                    if addr is None:
                        raise ValueError("Unknown Route")
                    if not self.is_upstream_active(addr):
                        raise ConnectionError("Upstream unavailable")
                    if not self.server_connection:
                        self.open_connection(addr)
                    else:
                        self.selector.modify(
                            self.server_socket, selectors.EVENT_WRITE, data=self
                        )
            elif event & selectors.EVENT_READ and fileobj is self.server_socket:
                print("receiving from server")
                headers, body = self.server_connection.receive_resp(self.set_activity)
                if headers and body:
                    self.set_resp_data(headers, body)
                    self.selector.modify(
                        self.client_socket,
                        selectors.EVENT_WRITE,
                        data=self,
                    )
                    # print("done receiving from server")
            elif event & selectors.EVENT_WRITE and fileobj is self.client_socket:
                # print(f"data before sending for serialization: {self.response_data}")
                print("sending reply to client")
                is_done = self.client_connection.send_response(
                    self.response_data, self.set_activity
                )
                self.update_buckets(time.time() - self.req_received_at)
                if is_done:
                    self.selector.modify(
                        self.client_socket,
                        selectors.EVENT_READ,
                        data=self,
                    )
            elif event & selectors.EVENT_WRITE and fileobj is self.server_socket:
                print("sending to server")
                is_done = self.server_connection.send_request(
                    self.request_data, self.set_activity
                )
                if is_done:
                    self.selector.modify(
                        self.server_socket,
                        selectors.EVENT_READ,
                        data=self,
                    )
                print("sending done")
        except Exception as e:
            print(f"An Exception occured {e}")
        # print(traceback.print_exc())
