from typing import List

import dns


class Request:
    name: str
    type: str

    def __init__(self, name: str, type: str):
        self.name = name
        self.type = type

    def is_valid_request(self):
        return self.type in ['A', 'NS', 'MX']


class ResponseRecord:
    type: dns.rdatatype.RdataType
    value: str

    def __init__(self, type, value):
        self.type = type
        self.value = value

    def __str__(self):
        return str(self.type) + " " + self.value


class Response:
    name: str
    type: str
    response_records: List[ResponseRecord]
    query_time: int
    when: str
    msg_size_rcvd: int

    def __init__(self, name: str, type: str, response_records: List[ResponseRecord], query_time: int, when: str, msg_size_rcvd: int):
        self.name = name
        self.type = type
        self.response_records = response_records
        self.query_time = query_time
        self.when = when
        self.msg_size_rcvd = msg_size_rcvd

    def __str__(self):
        return "Name: " + self.name + "\nType: " + self.type \
               + "\nResponse records: " + \
               str([str(response_record) for response_record in self.response_records]) + \
               "\nQuery time: " + str(self.query_time) + " ms\n"
