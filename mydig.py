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


# Code for part A
def resolve_dns(request: Request) -> Response:
    start_time = time.time()
    answer_records, authority_records, msg_size_rcvd = __resolve_dns__(request)
    end_time = time.time()

    return Response(
        name=request.name,
        type=request.type,
        answer_records=answer_records,
        authority_records=authority_records,
        query_time=int((end_time - start_time) * 1000),
        when=str(datetime.datetime.now()),
        msg_size_rcvd=msg_size_rcvd
    )


def __resolve_dns__(request: Request) -> Tuple[
    List[ResponseRecord],
    List[ResponseRecord],
    int
]:
    request_message = __generate_request_message__(request)

    root_server_ips = []
    with open(ROOT_SERVER_IPV4S_FILE_NAME, "r") as root_file:
        root_server_ips = [root_server_ip.rstrip('\n') for root_server_ip in root_file.readlines()]

    final_answer_records = []
    final_authority_records = []
    final_message_size = 0
    name_server_ips = root_server_ips

    while True:
        response_message = __resolve_dns_from_servers__(request_message, name_server_ips)
        final_message_size = sys.getsizeof(response_message.to_wire()) if response_message is not None else 0

        # DNS resolution failed
        if response_message is None:
            break
        # Did not get an answer, so pass the request on to name servers
        elif len(response_message.answer) == 0 and (request.type == "A" or len(response_message.additional) > 0):
            authority_records = __parse_dns_records_from_section__(response_message.authority)

            # In some cases, we get an SOA response for A requests, which cannot be resolved further
            if True in (authority_record.type == dns.rdatatype.SOA for authority_record in authority_records):
                final_authority_records += authority_records
                return final_answer_records, final_authority_records, final_message_size

            name_server_ips = __parse_name_server_ips_from_response__(response_message)
        else:
            # Got an answer, either in the 'Answer' or 'Authority' section
            answer_records = __parse_dns_records_from_section__(response_message.answer)
            authority_records = __parse_dns_records_from_section__(response_message.authority) \
                if len(response_message.authority) > 0 else []

            final_answer_records += answer_records
            final_authority_records += authority_records

            # got a CNAME record. Resolve as an 'A' request from root
            if len(answer_records) == 1 and answer_records[0].type == dns.rdatatype.CNAME:
                request_message = __generate_request_message__(Request(
                    name=answer_records[0].value,
                    type="A"
                ))
                name_server_ips = root_server_ips
            # we are done
            else:
                return final_answer_records, final_authority_records, final_message_size

    # DNS resolution failed
    return [], [], 0


# Try every server until we get a DNS response
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

    if len(response_message.additional) > 0:
        for rrset in response_message.additional:
            if rrset.rdtype == dns.rdatatype.A:
                name_server_ips += [item.address for item in rrset.items]
    else:
        authority_records = __parse_dns_records_from_section__(response_message.authority)
        for authority_record in authority_records:
            new_request =  Request(
                name=authority_record.value,
                type='A'
            )
            answer_records, _, _ = __resolve_dns__(new_request)
            name_server_ips += [answer_record.value for answer_record in answer_records
                                if answer_record.type == dns.rdatatype.A]

    return name_server_ips


def __parse_dns_records_from_section__(section) -> List[ResponseRecord]:
    results = []

    for rrset in section:
        for item in rrset.items:
            if item.rdtype == dns.rdatatype.A:
                results.append(
                    ResponseRecord(type=item.rdtype, value=item.address))
            elif item.rdtype == dns.rdatatype.MX:
                results.append(
                    ResponseRecord(type=item.rdtype, value=item.exchange.to_text()))
            elif item.rdtype == dns.rdatatype.CNAME or item.rdtype == dns.rdatatype.NS:
                results.append(
                    ResponseRecord(type=item.rdtype, value=item.target.to_text()))
            elif item.rdtype == dns.rdatatype.SOA:
                results.append(
                    ResponseRecord(type=item.rdtype, value=item.mname.to_text() + " " + item.rname.to_text()))

    return results
