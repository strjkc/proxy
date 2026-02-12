import time
import errno


class C_Mag_Connection:
    def __init__(self, socket, timeout, last_active_time):
        self.socket = socket
        self.timeout = timeout
        self.last_active_time = last_active_time


class C_Mag:
    def __init__(self, selector):
        self.selector = selector
        self.connections = []

    def add_connection(self, c_mag_connection):
        if c_mag_connection:
            self.connections.append(c_mag_connection)

    def modify_last_act_time(self, socket, new_time):
        for connection in self.connections:
            if socket is connection.socket:
                connection.last_active_time = new_time
                return
        raise ValueError("Socket not found")

    def reap_connections(self):
        for connection in self.connections:
            timeout = time.time() - connection.last_active_time
            if timeout > connection.timeout:
                try:
                    print(f"Closing connection {connection.socket}")
                    self.selector.unregister(connection.socket)
                    connection.socket.close()
                    self.connections.remove(connection)
                except (OSError, ValueError):
                    print(f"Connection {connection.socket} already closed")
                    self.connections.remove(connection)
                except Exception as e:
                    print(f"C_Mag reap error {e} {type(e).__name__}")
