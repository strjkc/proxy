import pytest
import proxy
import time
import types


def test_health_check_sent(mocker):
    upstream_status = {
        ("127.0.0.1", 8080): types.SimpleNamespace(status=True, checked=time.time()),
        ("127.0.0.1", 8081): types.SimpleNamespace(status=True, checked=time.time()),
    }
    arr = []
    mocker.patch.object(
        proxy,
        "send_health_check",
        side_effect=lambda *args: arr.append("Health Check Sent"),
    )
    start_time = time.time()
    curr_time = time.time()

    while curr_time - start_time < 9:
        curr_time = time.time()
        proxy.check_health(curr_time, upstream_status, 3)
    print(arr)
    assert len(arr) == 6


def test_status_change():
    pass
