import datetime
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
    dns_records = __resolve_dns__(request)

    if request.type == 'A':
        while len(dns_records) > 0 and dns.rdatatype.CNAME == dns_records[-1][0]:
            new_request = Request(dns_records[-1][1], request.type)
            dns_records += __resolve_dns__(new_request)

    end_time = time.time()
    return __build_response__(request, dns_records, int((end_time - start_time)*1000))


def __resolve_dns__(request: Request) -> List[Tuple[dns.rdatatype.RdataType, str]]:
    request_message = __generate_request_message__(request)

    root_server_ips = []
    with open(ROOT_SERVER_IPV4S_FILE_NAME, "r") as root_file:
        root_server_ips = [root_server_ip.rstrip('\n') for root_server_ip in root_file.readlines()]

    response_message = __resolve_dns_from_servers__(request_message, root_server_ips)

    while response_message and len(response_message.answer) == 0:
        name_server_ips = __parse_name_server_ips_from_response__(response_message)
        response_message = __resolve_dns_from_servers__(request_message, name_server_ips)

    results = []

    # todo better handling?
    if response_message is None:
        return results

    for rrset in response_message.answer:
        for item in rrset.items:
            if item.rdtype == dns.rdatatype.A:
                results.append((item.rdtype, item.address))
            elif item.rdtype == dns.rdatatype.MX:
                results.append((item.rdtype, item.exchange.to_text()))
            elif item.rdtype == dns.rdatatype.CNAME or item.rdtype == dns.rdatatype.NS:
                results.append((item.rdtype, item.target.to_text()))

    return results


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


def __build_response__(request: Request, dns_records: List[Tuple[dns.rdatatype.RdataType, str]], time_elapsed_ms: int) -> Response:
    return Response(
        name = request.name,
        type = request.type,
        response_records=[
            ResponseRecord(dns_record[0], dns_record[1]) for dns_record in dns_records
        ],
        query_time=time_elapsed_ms,
        when=str(datetime.datetime.now().timestamp()),
        msg_size_rcvd=0
    )
