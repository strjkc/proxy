import pytest
from connection_manager import C_Mag, C_Mag_Connection
import time
import selectors


@pytest.fixture
def setup(mocker):
    print("fixture running")
    m_socket = mocker.Mock()
    m_socket.close.return_value(("Closed", time.time()))
    c1 = C_Mag_Connection(m_socket, 5, time.time())
    c2 = C_Mag_Connection(m_socket, 7, time.time())
    c3 = C_Mag_Connection(m_socket, 12, time.time())
    return c1, c2, c3


def test_reap(mocker):
    arr = []

    def sf():
        arr.append(("Closed", time.time()))

    m_socket = mocker.Mock()

    m_selector = mocker.Mock()
    m_socket.close.side_effect = sf

    m_socket2 = mocker.Mock()
    m_socket2.close.side_effect = sf

    m_socket3 = mocker.Mock()
    m_socket3.close.side_effect = sf

    c1_time = time.time()
    c2_time = time.time()
    c3_time = time.time()

    c1 = C_Mag_Connection(m_socket, 2, c1_time)
    c2 = C_Mag_Connection(m_socket2, 7, c2_time)
    c3 = C_Mag_Connection(m_socket3, 12, c3_time)

    timeouts = [(2, c1_time), (7, c2_time), (12, c3_time)]

    connections = [c1, c2, c3]
    c_mag = C_Mag(m_selector)
    c_mag.connections = connections
    start_time = time.time()
    curr_time = time.time()
    while curr_time - start_time < 12:
        curr_time = time.time()
        c_mag.reap_connections()
    for ret, t in zip(arr, timeouts):
        print(f"{t[0]} == {int(ret[1] - t[1])}")
        assert t[0] == int(ret[1] - t[1])
    print(f"arr {arr}")
