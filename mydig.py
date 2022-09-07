from typing import Optional

import dns.name
import dns.query
from dns.message import make_query, Message
from models import Request, Response

DNS_QUERY_TIMEOUT = 1
ROOT_SERVER_IPV4S_FILE_NAME = "./root_server_ipv4s.txt"


def resolve_dns(request: Request) -> Response:
    request_message = __generate_request_message__(request)

    root_server_ips = []
    with open(ROOT_SERVER_IPV4S_FILE_NAME, "r") as root_file:
        root_server_ips = [root_server_ip.rstrip('\n') for root_server_ip in root_file.readlines()]

    for root_server_ip in root_server_ips:
        response_message = __resolve_dns__(request_message, root_server_ip)
        if response_message is not None:
            break



def __resolve_dns__(request_message: Message, root_server_name: str) -> Optional[Message]:
    # todo return None if query fails
    return dns.query.udp(
        request_message,
        root_server_name,
        DNS_QUERY_TIMEOUT
    )

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


def __generate_response_from_message__(response_message: Message) -> Response:
    # todo
    pass
