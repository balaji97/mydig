import datetime
import sys
import time
from typing import Optional, List, Tuple

import dns.name
import dns.query
from dns.message import make_query, Message
from models import Request, Response, ResponseRecord

DNS_QUERY_TIMEOUT = 1
ROOT_SERVER_IPV4S_FILE_NAME = "./root_server_ipv4s.txt"


def resolve_dns(request: Request) -> Response:
    start_time = time.time()
    answer_records, authority_records, msg_size_rcvd = __resolve_dns__(request)

    if request.type == 'A':
        while len(answer_records) > 0 and dns.rdatatype.CNAME == answer_records[-1][0]:
            new_request = Request(answer_records[-1][1], request.type)
            new_answer_records, new_authority_records, msg_size_rcvd = __resolve_dns__(new_request)
            answer_records += new_answer_records
            authority_records = new_authority_records

    end_time = time.time()
    return __build_response__(
        request, answer_records, authority_records, int((end_time - start_time) * 1000), msg_size_rcvd)


def __resolve_dns__(request: Request) -> Tuple[
    List[Tuple[dns.rdatatype.RdataType, str]],
    List[Tuple[dns.rdatatype.RdataType, str]],
    int
]:
    request_message = __generate_request_message__(request)

    root_server_ips = []
    with open(ROOT_SERVER_IPV4S_FILE_NAME, "r") as root_file:
        root_server_ips = [root_server_ip.rstrip('\n') for root_server_ip in root_file.readlines()]

    response_message = __resolve_dns_from_servers__(request_message, root_server_ips)

    while response_message and len(response_message.answer) == 0 and len(response_message.additional) != 0:
        name_server_ips = __parse_name_server_ips_from_response__(response_message)
        response_message = __resolve_dns_from_servers__(request_message, name_server_ips)

    # todo better handling?
    if response_message is None:
        return [], [], 0

    return __parse_dns_records_from_section__(response_message.answer), __parse_dns_records_from_section__(
        response_message.authority), sys.getsizeof(response_message)


def __resolve_dns_from_servers__(request_message: Message, dns_server_ips: List[str]) -> Optional[Message]:
    response_message = None
    for dns_server_ip in dns_server_ips:
        response_message = __resolve_dns_from_server__(request_message, dns_server_ip)
        if response_message is not None:
            break

    return response_message


def __resolve_dns_from_server__(request_message: Message, root_server_name: str) -> Optional[Message]:
    response_message = None
    try:
        response_message = dns.query.udp(
            request_message,
            root_server_name,
            DNS_QUERY_TIMEOUT
        )
    except Exception as e:
        print("Error when querying DNS server " + root_server_name + " error message " + e.msg)
        response_message = None
    finally:
        return response_message


def __generate_request_message__(request: Request) -> Message:
    if request.type == 'A':
        dns_type = dns.rdatatype.A
    elif request.type == 'NS':
        dns_type = dns.rdatatype.NS
    else:
        dns_type = dns.rdatatype.MX

    return make_query(
        dns.name.from_text(request.name),
        dns_type
    )


def __parse_name_server_ips_from_response__(response_message: Message) -> List[str]:
    name_server_ips = []
    for rrset in response_message.additional:
        if rrset.rdtype == dns.rdatatype.A:
            name_server_ips += [item.address for item in rrset.items]

    return name_server_ips


def __parse_dns_records_from_section__(section) -> List[Tuple[dns.rdatatype.RdataType, str]]:
    results = []

    for rrset in section:
        for item in rrset.items:
            if item.rdtype == dns.rdatatype.A:
                results.append((item.rdtype, item.address))
            elif item.rdtype == dns.rdatatype.MX:
                results.append((item.rdtype, item.exchange.to_text()))
            elif item.rdtype == dns.rdatatype.CNAME or item.rdtype == dns.rdatatype.NS:
                results.append((item.rdtype, item.target.to_text()))
            elif item.rdtype == dns.rdatatype.SOA:
                pass

    return results


def __build_response__(request: Request, answer_records: List[Tuple[dns.rdatatype.RdataType, str]],
                       authority_records: List[Tuple[dns.rdatatype.RdataType, str]], time_elapsed_ms: int,
                       msg_size_rcvd: int) -> Response:
    return Response(
        name=request.name,
        type=request.type,
        answer_records=[
            ResponseRecord(dns_record[0], dns_record[1]) for dns_record in answer_records
        ],
        authority_records=[
            ResponseRecord(dns_record[0], dns_record[1]) for dns_record in authority_records
        ],
        query_time=time_elapsed_ms,
        when=str(datetime.datetime.now()),
        msg_size_rcvd=msg_size_rcvd
    )
