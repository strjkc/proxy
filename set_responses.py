def get_metrics_data():
    return {
        "Proto": "HTTP/1.1",
        "Code": 200,
        "Message": "OK",
        "Content-Type": "application/json",
        "Content-Length": 0,
    }


def get_client_timeout_reply_data():
    return {
        "Proto": "HTTP/1.1",
        "Code": 408,
        "Message": "Request Timeout",
        "Connection": "close",
    }


def get_server_timeout_reply_data():
    return {
        "Proto": "HTTP/1.1",
        "Code": 504,
        "Message": "Gateway Timeout",
        "Connection": "close",
    }


def get_upstream_unavailable_data():
    return {
        "Proto": "HTTP/1.1",
        "Code": 503,
        "Message": "Service Unavailable",
        "Connection": "close",
    }


def get_long_headers_data():
    return {
        "Proto": "HTTP/1.1",
        "Code": 431,
        "Message": "Request Header Fields Too Large",
        "Connection": "close",
    }


def get_route_not_found_data():
    return {
        "Proto": "HTTP/1.1",
        "Code": 404,
        "Message": "Not Found",
        "Connection": "close",
    }
