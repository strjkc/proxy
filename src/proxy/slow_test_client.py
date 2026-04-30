import socket
import sys
import time
import selectors

selector = selectors.DefaultSelector()


def main(addr, buffer, inbuff):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(addr)
    sock.setblocking(False)
    dta = []
    selector.register(sock, selectors.EVENT_READ, data=dta)
    while True:
        try:
            time.sleep(1)
            event = selector.select(False)
            if buffer:
                sent = sock.send(buffer[:1])
                print(f"sent a byte to the server hehe: {buffer[:1]}")
                buffer = buffer[sent:]
            else:
                print("sending done")
                break
            if event:
                for k, v in event:
                    if v & selectors.EVENT_READ:
                        data = k.fileobj.recv(4096)
                        if data:
                            k.data.append(data)
        except BrokenPipeError as e:
            print("Server killed the connection")
            print(f"With the following response: {dta}")
            break

    print("Sending done")


if __name__ == "__main__":
    host = sys.argv[1]
    port = int(sys.argv[2])
    buff = b"GET /app HTTP/1.1\r\nHost:127.0.0.1\r\n\r\n"
    inbuff = b""
    main((host, port), buff, inbuff)
