import socket
import selectors
import types

host = "127.0.0.1"
port = 0

messages = [b"This is the first message", b"this is the second message"]
selector = selectors.DefaultSelector()

num_connections = 3


def start_connection():
    for i in range(0, num_connections):
        conn_id = i + 1
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.connect_ex((host, 8081))
        data = types.SimpleNamespace(
            conn_id=conn_id,
            data_received=0,
            msg_total=sum(len(message) for message in messages),
            messages=messages.copy(),
            outb=b"",
        )
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        selector.register(sock, events, data)


def handle_connection(key, mask):
    sock = key.fileobj
    data = key.data

    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)
        if recv_data:
            print(f"Received: {recv_data} from connection: {data.conn_id}")
            data.data_received += len(recv_data)
        if not recv_data or data.data_received == data.msg_total:
            print(f"Closing connection: {data.conn_id}")
            sock.close()
            selector.unregister(sock)
    if mask & selectors.EVENT_WRITE:
        if not data.outb and data.messages:
            data.outb = data.messages.pop(0)
        if data.outb:
            print(f"sending to server: {data.outb} from connection: {data.conn_id}")
            sent = sock.send(data.outb)
            data.outb = data.outb[sent:]


try:
    start_connection()
    while True:
        events = selector.select(False)
        for key, mask in events:
            if key.data is not None:
                handle_connection(key, mask)
except Exception as e:
    print(e)

# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#    s.bind((host, port))
#    s.connect((host, 8081))
#    s.sendall(b"Hello world")
#    data = s.recv(1024)
#
# print(f"Received data: {data}")
