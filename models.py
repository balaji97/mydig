from typing import Optional


class Request:
    name: str
    type: str

    def __init__(self, name: str, type: str):
        self.name = name
        self.type = type

    def is_valid_request(self):
        return self.type in ['A', 'NS', 'MX']


class Response:
    name: str
    type: str
    ip_address: Optional[str]
    query_time: int
    when: str
    msg_size_rcvd: int

    def __init__(self, name: str, type: str, ip_address: Optional[str], query_time: int, when: str, msg_size_rcvd: int):
        self.name = name
        self.type = type
        self.ip_address = ip_address
        self.query_time = query_time
        self.when = when
        self.msg_size_rcvd = msg_size_rcvd
