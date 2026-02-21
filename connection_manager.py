import logging
import time
import errno

logger = logging.getLogger(__name__)


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

    def obj_exists(self, socket):
        sockets = [connection.socket for connection in self.connections]
        if socket in sockets:
            return True
        return False

    def reap_connections(self):
        for connection in self.connections[:]:
            timeout = time.time() - connection.last_active_time
            print(
                f"for socket: {connection.socket} Last active time {connection.last_active_time}, current: {time.time()} time diff is : {timeout} and cleanup should occur when {connection.timeout}"
            )
            logger.info(
                f"for socket: {connection.socket} Last active time {connection.last_active_time}, current: {time.time()} time diff is : {timeout} and cleanup should occur when {connection.timeout}"
            )
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
