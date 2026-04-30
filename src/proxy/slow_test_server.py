import socket
import selectors
import time

selector = selectors.DefaultSelector()

dta = b"HTTP/1.1 200 OK\r\nHost:127.0.0.1\r\n\r\n"
recvdta = []


def accept_connection(socket):
    print("accepting connection")
    conn, addr = socket.accept()
    conn.setblocking(False)
    selector.register(conn, selectors.EVENT_READ | selectors.EVENT_WRITE, data=recvdta)


addr = ("127.0.0.1", 8585)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(addr)
sock.listen()
print(f"started listening on {addr}")
sock.setblocking(False)
selector.register(sock, selectors.EVENT_READ | selectors.EVENT_WRITE, data=None)

while True:
    events = selector.select(1)
    if events:
        try:
            for k, m in events:
                if k.data is None:
                    accept_connection(k.fileobj)
                else:
                    if m & selectors.EVENT_READ:
                        data = k.fileobj.recv(4096)
                        print(data)
                        recvdta.append(data)
                        # selector.modify(k.fileobj, selectors.EVENT_WRITE, data=k.data)
                        if not data:
                            print("client closed connection")
                            print(data)
                            k.fileobj.close()
                            selector.unregister(k.fileobj)
                            break
                    if m & selectors.EVENT_WRITE:
                        print(f"{dta[:1]}")
                        sent = k.fileobj.send(dta[:1])
                        dta = dta[sent:]
                        time.sleep(1)
        except BrokenPipeError as e:
            print("Client closed connection")
            print(recvdta)
        except Exception as e:
            print(e)
            print(recvdta)
