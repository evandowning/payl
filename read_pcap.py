import sys
import os
import dpkt
import socket

# DNS parsing code from: https://github.com/jeffsilverm/dpkt_doc/blob/master/decode_dns.py

type_table = {1:'A',        # IP v4 address, RFC 1035
              2:'NS',       # Authoritative name server, RFC 1035
              5:'CNAME',    # Canonical name for an alias, RFC 1035
              6:'SOA',      # Marks the start of a zone of authority, RFC 1035
             12:'PTR',      # Domain name pointer, RFC 1035
             13:'HINFO',    # Host information, RFC 1035
             15:'MX',       # Mail exchange, RFC 1035
             28:'AAAA',     # IP v6 address, RFC 3596
             16:'TXT',      # 
             33:'SRV',     # RFC 2782
             255:'ANY',     # all cached reco
             }


def hexify(x):
    "The strings from DNS resolver contain non-ASCII characters - I don't know why.  This function investigates that"
    toHex = lambda x:''.join([hex(ord(c))[2:].zfill(2) for c in x])
    return toHex(x)

# Decode DNS response
def decode_dns_response(rr, response_type):
    global type_table

    r_type = rr.type
    r_data = rr.rdata

    rr_string = ''

    if r_type == dpkt.dns.DNS_CNAME:
        rr_string = rr.cname
    elif r_type == dpkt.dns.DNS_A:
        if len(r_data) == 0:
            return 'unknown'
        rr_string = socket.inet_ntoa(r_data)
    elif r_type == dpkt.dns.DNS_NS:
        rr_string = rr.nsname
    elif r_type == dpkt.dns.DNS_AAAA:
        if len(r_data) == 0:
            return 'unknown'
        rr_string = socket.inet_ntop(socket.AF_INET6, r_data)
    elif r_type == dpkt.dns.DNS_PTR:
        rr_string = rr.ptrname
    elif r_type == dpkt.dns.DNS_SOA:
        rr_string = '{0},{1},{2},{3},{4},{5},{6}'.format(rr.mname,rr.rname,rr.serial,rr.refresh,rr.retry,rr.expire,rr.minimum)
    elif r_type == dpkt.dns.DNS_MX:
        rr_string = rr.mxname + ',' + rr.preference
    elif r_type == dpkt.dns.DNS_HINFO:
        rr_string = rr.rtext
    elif r_type == dpkt.dns.DNS_TXT:
        rr_string = rr.rtext
    elif r_type == dpkt.dns.DNS_SRV:
        rr_string = '{0},{1},{2},{3}'.format(rr.srvname,rr.port,rr.priority,rr.weight)
    else :
        if r_type in type_table:
            rr_string = hexify(r_data)
        else:
            return 'unknown'

    return '{0}\\{1}'.format(type_table[r_type],rr_string)

# Parse DNS response payload
def parse_rr(payload, t):
    rv = ''

    # For each response record
    for rr in payload:
        rr_string = decode_dns_response(rr,t)

        if rr_string == 'unknown':
            continue

        rv += ',{0}'.format(rr_string)

    # Remove leading ','
    rv = rv[1:]

    return rv

# Parses pcap file and extracts string values
def readPcap(fn):
    global type_table

    payload = list()

    # Open pcap file for reading
    f = open(fn,'rb')
    pcap = dpkt.pcap.Reader(f)

    # For each packet
    for ts,buf in pcap:
        try:
            # Extract data from pcap file
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            proto_data = ip.data

            # DNS response
            if (proto_data.sport == 53):
                dns_payload = dpkt.dns.DNS(proto_data.data)

                dns_response_str = ''

                # Parse nameserver response
                dns_response_str += parse_rr(dns_payload.ns,'NS')
                # Parse authoritative nameserver response
                dns_response_str += parse_rr(dns_payload.an,'AN')
                # Parse additional responses
                dns_response_str += parse_rr(dns_payload.ar,'AR')

                # Parse rest of record
                dns_payload_str = '{0}\\{1}\\{2}\\{3}\\{4}\\{5}\\{6}\\{7}'.format(dns_payload.id,
                                                                                  dns_payload.qr,
                                                                                  dns_payload.opcode,
                                                                                  dns_payload.rcode,
                                                                                  len(dns_payload.an),
                                                                                  len(dns_payload.ns),
                                                                                  len(dns_payload.ar),
                                                                                  dns_response_str)

                payload.append(dns_payload_str)

            # DNS request
            elif (proto_data.dport == 53):
                dns_payload = dpkt.dns.DNS(proto_data.data)

                # Parse request
                dns_payload_str = '{0}\\{1}\\{2}\\{3}\\{4}\\{5}\\{6}\\{7}\\{8}\\{9}'.format(dns_payload.id,
                                                                                            dns_payload.qr,
                                                                                            dns_payload.opcode,
                                                                                            dns_payload.rcode,
                                                                                            len(dns_payload.an),
                                                                                            len(dns_payload.ns),
                                                                                            len(dns_payload.ar),
                                                                                            dns_payload.qd[0].name,
                                                                                            dns_payload.qd[0].type,
                                                                                            dns_payload.qd[0].type)

                payload.append(dns_payload_str)

            # HTTP response or request
            elif ((proto_data.sport == 80) or (proto_data.dport == 80)):
                payload.append(str(proto_data.data))

            # NOTE: temporary. ports used in attack
            elif (proto_data.sport == 1924 and proto_data.dport == 1957):
                payload.append(str(proto_data.data))

        except Exception as e:
            # Close file
            f.close()

            print 'Error: ', str(e)
            sys.exit(1)

    # Close file
    f.close()

    return payload

# Retrieves payload features of samples
def getPayloadStrings(sample):
    payload = list()

    for fn,label in sample:
        print 'scanning ', fn

        # Read in individual payloads from pcap file
        payloads = readPcap(fn)

        # Append payloads with labels
        for p in payloads:
            if len(p) > 0:
                payload.append((p,label))

    return payload
