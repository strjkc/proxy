import time
import socket
import selectors
import types
from appserver import Message

host = "127.0.0.1"
port = 8081


def accept(sock):
    # ako primamo novu konekciju ovde samo inicijalizujemo parametre za tu konekciju
    conn, addr = sock.accept()
    print(f"connection established for {addr}")
    conn.setblocking(False)
    data = Message(conn, selector, addr)
    # data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    # hocemo da se pretplatimo i na read i na write evente
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    selector.register(conn, events, data=data)


def handle_connection(key, event):
    sock = key.fileobj
    data = key.data
    if event & selectors.EVENT_READ:
        recv_data = sock.recv(1024)
        if recv_data:
            print(f"Received {recv_data} from {data.addr}")
            data.outb += recv_data
        else:
            print(f"closing connection: {data.addr}")
            selector.unregister(sock)
            sock.close()
    if event & selectors.EVENT_WRITE:
        if data.outb:
            print(f"Sending {data.outb} to {data.addr}")
            sent = sock.send(data.outb)
            # ako nesto nije poslato, bice poslato kada petlja ponovo dodje do ovog koraka
            data.outb = data.outb[sent:]


selector = selectors.DefaultSelector()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((host, port))
sock.listen()
print(f"Server listening on: {host}:{port}")
sock.setblocking(False)
# kada pozovemo register funkciju to znaci za ovaj objekat i ovaj tip eventa mi javljaj, a ove podatke povezi sa tim objektom
# i onda nam select funkcija vraca evente od kernela vezane za taj objekat i taj tip eventa.
selector.register(sock, selectors.EVENT_READ, data=None)

try:
    while True:
        # vraca tupple gde je na prvom mestu objekat sa raznim podacima, a event je bit maska
        events = selector.select(timeout=False)
        if not events:
            time.sleep(0.001)
        for key, event in events:
            # ako je key.data none to znaci da je to onaj event na koji smo se pretplatili na pocetku, tj da je od listening socketa
            if key.data is None:
                accept(key.fileobj)
            else:
                key.data.handle_event(event)
                # ako nije to znaci da je od aktivnog soketa, znaci treba da primamo ili saljemo podatke
            # handle_connection(key, event)
except Exception as e:
    print(e)
    selector.unregister(sock)
    sock.close()


# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#    s.bind((host, port))
#    s.listen()
#    conn, addr = s.accept()
#    with conn:
#        print(f"Connected by {addr}")
#        while True:
#            data = conn.recv(1024)
#            print(data)
#            if not data:
#                break
#            conn.sendall(data + b" and your mom")
