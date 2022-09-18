from typing import List, Optional

import dns


# Simple input/output wrapper objects shared by mydig and mydig_dnssec libraries
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
    answer_records: List[ResponseRecord]
    authority_records: List[ResponseRecord]
    query_time: int
    when: str
    msg_size_rcvd: int
    dnssec_error: Optional[str]

    def __init__(self, name: str, type: str, answer_records: List[ResponseRecord], authority_records: List[ResponseRecord], query_time: int, when: str, msg_size_rcvd: int, dnssec_error: Optional[str] = None):
        self.name = name
        self.type = type
        self.answer_records = answer_records
        self.authority_records = authority_records
        self.query_time = query_time
        self.when = when
        self.msg_size_rcvd = msg_size_rcvd
        self.dnssec_error= dnssec_error

    def __str__(self):
        return "Question section - " + "Name: " + self.name + " Type: " + self.type \
               + "\nAnswer section - " + \
               str([str(response_record) for response_record in self.answer_records]) + \
               "\nAuthority section - " + \
               str([str(response_record) for response_record in self.authority_records]) + \
               "\nMetadata - Query time: " + str(self.query_time) + "ms When: " + self.when + \
               " Msg size rcvd: " + str(self.msg_size_rcvd) + "\n" + \
               "DNSSEC error message: " + str(self.dnssec_error) + "\n"
