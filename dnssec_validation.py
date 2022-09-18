from typing import Optional

import dns.rdatatype
import dns.resolver
import dns.name
import dns.message
import dns.query
from dns.message import Message

from models import Request
from mydig import resolve_dns

keys = dict()

DNSKEY_TIMEOUT = 1


def validate_response(response_message: Message) -> Optional[str]:
    ds_records = []
    record_signature_pairs = []

    for section in response_message.sections:
        prev = None
        for rrset in section:
            if rrset.rdtype == dns.rdatatype.DS:
                ds_records.append(rrset)

            if rrset.rdtype == dns.rdatatype.RRSIG and prev is not None:
                record_signature_pairs.append((prev, rrset))
            elif rrset.rdtype != dns.rdatatype.RRSIG:
                prev = rrset

    # If we did not get the answer, we need to drill down to next zone
    # If that zone does not have a DS record, then DNSSEC is not supported
    if len(response_message.answer) == 0 and len(ds_records) == 0:
        return "DNSSEC not supported."

    for ds_record in ds_records:
        err_msg = __fetch_and_validate_keys__(ds_record)
        if err_msg is not None:
            return err_msg

    for record, rrsig_record in record_signature_pairs:
        try:
            dns.dnssec.validate(record, rrsig_record, keys)
        except:
            return "DNSSEC RRSIG record verification failed"

    return None


def __fetch_and_validate_keys__(ds_record) -> Optional[str]:
    result = resolve_dns(Request(
        name=ds_record.name.to_text(),
        type="NS"
    ))
    ns_names = [ns_record.value for ns_record in result.answer_records + result.authority_records if ns_record.type == dns.rdatatype.NS]
    ns_ips = []
    for ns_name in ns_names:
        result = resolve_dns(Request(
            name=ns_name,
            type="A"
        ))
        ns_ips += [ns_ip_record.value for ns_ip_record in result.answer_records if ns_ip_record.type == dns.rdatatype.A]

    err_msg = "Could not fetch DNSKEY"
    for ns_ip in ns_ips:
        try:
            key_response = dns.query.udp(
                dns.message.make_query(ds_record.name, dns.rdatatype.DNSKEY, want_dnssec=True),
                ns_ip)
            err_msg = None
            break
        except:
            continue

    if err_msg is not None:
        return err_msg

    ksk_record = None
    dnskey_record = None
    rrsig_record = None

    for rrset in key_response.answer:
        if rrset.rdtype == dns.rdatatype.DNSKEY:
            for item in rrset:
                if item.flags == 257:
                    ksk_record = item
                    break

        if rrset.rdtype == dns.rdatatype.DNSKEY:
            dnskey_record = rrset
        elif rrset.rdtype == dns.rdatatype.RRSIG:
            rrsig_record = rrset

    if None in [ksk_record, dnskey_record, rrsig_record]:
        return "DNSSEC not enabled"

    # todo validate ksk_record using ds_record
    try:
        keys[ds_record.name] = dnskey_record
        dns.dnssec.validate(dnskey_record, rrsig_record, keys)
    except:
        del keys[ds_record.name]
        return "Failed to validate signature of DNSKEY record"

    for ds_digest in ds_record:
        if ds_digest.algorithm != ksk_record.algorithm:
            continue

        ksk_digest = dns.dnssec.make_ds(ds_record.name, ksk_record, __parse_algorithm__(ds_digest.algorithm))
        if ds_digest.digest == ksk_digest.digest:
            return None

    return "DS validation for KSK failed"


# Only supports RSA
def __parse_algorithm__(algorithm_enum) -> str:
    algorithms = ['MD5', 'SHA1', 'SHA128', 'SHA256', 'SHA512']
    for alg in algorithms:
        if alg in algorithm_enum.name:
            return alg

    return 'SHA256'


# Initialize in main before starting dnssec flow
def __init__():
    root_name = dns.name.from_text(".")
    keys[root_name] = dns.resolver.resolve(qname='.', rdtype=dns.rdatatype.DNSKEY).rrset
