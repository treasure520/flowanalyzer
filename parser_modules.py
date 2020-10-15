# Copyright (c) 2017, Manito Networks, LLC
# All rights reserved.

### Packed Integer Parsers ###
class name_lookups(object):
    import socket
    import time
    from site_category import site_categories

    dns_cache = {}  # Name cache

    # Multicast per http://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml
    special_ips = {
        '255.255.255.255': 'Broadcast',
        '127.0.0.1': 'Localhost',
        '224.0.0.0': 'Multicast',
        '224.0.0.1': 'All Hosts Multicast',
        '224.0.0.2': 'All Routers Multicast',
        '224.0.0.4': 'DVMRP Multicast',
        '224.0.0.5': 'OSPF Router Multicast',
        '224.0.0.6': 'OSPF Designated Router Multicast',
        '224.0.0.9': 'RIPv2 Multicast',
        '224.0.0.10': 'EIGRP Multicast',
        '224.0.0.12': 'DHCP Server / Relay',
        '224.0.0.13': 'PIMv2 Multicast',
        '224.0.0.14': 'RSVP Encapsulation Multicast',
        '224.0.0.18': 'VRRP Multicast',
        '224.0.0.19': 'IS-IS Multicast',
        '224.0.0.20': 'IS-IS Multicast',
        '224.0.0.21': 'IS-IS Multicsast',
        '224.0.0.22': 'IGMPv3 Multicast',
        '224.0.0.102': 'HSRPv2 Multicast',
        '224.0.0.252': 'Link-local Multicast Name Resolution',
        '224.0.0.253': 'Teredo tunneling client discovery address',
    }

    # Add special IPs to dns_cache
    for key in special_ips:
        dns_cache[key] = {}
        dns_cache[key]['FQDN'] = special_ips[key]
        dns_cache[key]['Domain'] = special_ips[key]
        dns_cache[key]['Content'] = 'Uncategorized'

    second_level_domains = {
        'co.id',  # Indonesia
        'co.in',  # India
        'co.jp',  # Japan
        'co.nz',  # New Zealand
        'co.uk',  # United Kingdom
        'co.za',  # South Africa
        'com.ar',  # Argentina
        'com.au',  # Australlia
        'com.bn',  # Brunei
        'com.br',  # Brazil
        'com.cn',  # People's Republic of China
        'con.gh',  # Ghana
        'com.hk',  # Hong Kong
        'com.mx',  # Mexico
        'com.sh',  # Singapore
        'edu.au',  # Australia
        'net.au',  # Australia
        'net.il',  # Israel
        'org.au',  # Australia
    }

    def __init__(self):
        return

    def ip_names(self, ip_version: int, ip_addr: str) -> dict:
        '''
        DNS reverse lookups for SRC and DST IP addresses

        Args:
            ip_version (int): Internet Protocol version
            ip_addr (str): IP address for lookup

        Returns:
            dict: {Content, Domain, Expires, FQDN}
            '''

        # if ip_version == 4:

        if ip_addr not in self.dns_cache:  # Not already cached
            # Record cache
            self.dns_cache[ip_addr] = {}
            self.dns_cache[ip_addr]['Expires'] = int(self.time.time()) + 1800

            try:
                ip_lookup = str(self.socket.getfqdn(
                    ip_addr))  # Run reverse lookup
            except Exception as lookup_message:  # DNS lookup failed
                print(lookup_message)
                return False

            # Successful lookup
            if ip_lookup != ip_addr:
                # Update the local cache
                self.dns_cache[ip_addr]['FQDN'] = ip_lookup  # FQDN

                # Parse the FQDN for Domain information
                if '.' in ip_lookup:
                    fqdn_exploded = ip_lookup.split('.')  # Blow it up

                    # Grab TLD and second-level domain
                    domain = str(fqdn_exploded[-2]) + \
                        '.' + str(fqdn_exploded[-1])

                    # Check for .co.uk, .com.jp, etc…
                    if domain in self.second_level_domains:
                        domain = str(fqdn_exploded[-3]) + '.' + str(domain)
                # Hostname, no domain
                else:
                    domain = ip_lookup

                self.dns_cache[ip_addr]['Domain'] = domain

                # Documented site with Content
                if self.dns_cache[ip_addr]['Domain'] in self.site_categories:
                    self.dns_cache[ip_addr]['Content'] = self.site_categories[self.dns_cache[ip_addr]['Domain']]
                else:
                    # Default contenet; Normalize graphs
                    self.dns_cache[ip_addr]['Content'] = 'Uncategorized'

            # No DNS record, use IP instead
            else:
                self.dns_cache[ip_addr]['FQDN'] = ip_addr  # Normalize graphs
                self.dns_cache[ip_addr]['Domain'] = ip_addr  # Normalize graphs
                # Default content; Normalize graphs
                self.dns_cache[ip_addr]['Content'] = 'Uncategorized'
        return self.dns_cache[ip_addr]

### Packed Integer Parsers ###


class int_parse(object):
    import struct
    from struct import unpack

    def __init__(self):
        return

    def integer_unpack(self, packed_data: struct, pointer: int, field_size: int) -> str:
        '''
        Unpcak an Integer

        Args:
            packed_data (struct): Packed data
            pointer (int): Current unpack location
            field_size (int): Length of data to unpack

        Returns:
            str: IPv4 Address
        '''
        if field_size == 1:
            return self.unpack('!B', packed_data[pointer: pointer + field_size])[0]
        elif field_size == 2:
            return self.unpack('!H', packed_data[pointer: pointer + field_size])[0]
        elif field_size == 4:
            return self.unpack('!I', packed_data[pointer: pointer + field_size])[0]
        elif field_size == 8:
            return self.unpack('!Q', packed_data[pointer: pointer + field_size])[0]
        else:
            return False

### Packed IP Parsers (Netflow v5, Netflow v9, IPFIX) ###


class ip_parse(object):
    import socket
    import struct

    # Windows socket.inet_ntop support via win_inet_pton
    try:
        import win_inet_pton
    except ImportError:
        pass

    def __init__(self):
        return

    # Unpack IPv4
    def parse_ipv4(self, packed_data: struct, pointer: int, field_size: int) -> str:
        '''
        Unpack IPv4 address

        Args:
            packed_data (struct): Packed data
            pointer (int): Current unpack location
            field_size (int): Length of data to unpack

        Returns:
            str: IPv4 Address
        '''
        payload = self.socket.inet_ntoa(
            packed_data[pointer: pointer + field_size])
        return payload

    # Unpack IPv6
    def parse_ipv6(self, packed_data: struct, pointer: int, field_size: int) -> str:
        '''
        Unpack IPv6 address

        Args:
            packed_data (struct): Packed data
            pointer (int): Current unpack location
            field_size (int): Length of data to unpack

        Returns:
            str: IPv6 address
        '''
        payload = self.socket.inet_ntop(
            self.socket.AF_INET6, packed_data[pointer: pointer + field_size])
        return payload

### Generic MAC Address Parsers ###


class mac_address(object):
    import struct

    def __init__(self):
        # See the following for MAC OUI information:
        # http://www.iana.org/assignments/ethernet-numbers/ethernet-numbers.xhtml
        # https://tools.ietf.org/html/rfc7042
        self.mac_oui_data = {
            '005056': {'Vendor': 'VMware', 'Type': 'Virtualization'},
            '00005E': {'Vendor': 'IANA', 'Type': 'Unicast'},
            '01000C': {'Vendor': 'Cisco', 'Type': 'Logical'},
            '01005E': {'Vendor': 'IANA', 'Type': 'Multicast'},
            '0180C2': {'Vendor': 'IEEE', 'Type': 'Logical'},
            '0A0027': {'Vendor': 'Oracle', 'Type': 'Virtualization'},
            '2C0E3D': {'Vendor': 'Samsung', 'Type': 'Physical'},
            '333300': {'Vendor': 'IPv6', 'Type': 'Virtualization'},
            '48F8B3': {'Vendor': 'Linksys', 'Type': 'Physical'},
            '5855CA': {'Vendor': 'Apple', 'Type': 'Physical'},
            '74C63B': {'Vendor': 'AzureWave Technology', 'Type': 'Physical'},
            '74D435': {'Vendor': 'Giga-Byte Technology', 'Type': 'Physical'},
            'FFFFFF': {'Vendor': 'Broadcasat', 'Type': 'Logical'},
        }

    # MAC passed as Python list, 6 elements
    def mac_parse(self, mac: list) -> tuple:
        '''
        Parse MAC address passed as Python list(6) that has already been unpacked

        Args:
            mac (list): List with (6) elemetns

        Returns:
            tuple: (MAC Address:str, MAC OUI:str)
        '''
        mac_list = []
        for mac_item in mac:
            mac_item_hex = hex(mac_item).replace(
                '0x', '')  # Strip leading characters
            if len(mac_item_hex) == 1:
                # Handle leading zeros and double-0's
                mac_item_hex = str('0' + mac_item_hex)
            mac_list.append(mac_item_hex)
        # Format MAC as 00:11:22:33:44:AA
        parsed_mac = (':'.join(mac_list)).upper()
        # Format MAC OUI as 001122
        parsed_mac_oui = (''.join(mac_list[0:3])).upper()
        return (parsed_mac, parsed_mac_oui)

    def mac_packed_parse(self, packed_data: 'xdr', pointer: int, field_size: int) -> tuple:
        '''
        Parse MAC addresses packed as packed bytes that first need to be unpacked

        Args:
            packed_data (xdr): Packed XDR data
            pointer (int): Current location for unpacking
            field_size (int): Size of the packed data

        Returns:
            tuple: (MAC Address: str, MAC OUI: str)
        '''
        mac_list = []
        mac_objects = self.struct.unpack(
            '!%dB' % field_size, packed_data[pointer:pointer + field_size])
        for mac_item in mac_objects:
            mac_item_hex = hex(mac_item).replace(
                '0x', '')  # Strip leading characters
            if len(mac_item_hex) == 1:
                # Handle leading zeros and double-0's
                mac_item_hex = str('0' + mac_item_hex)
            mac_list.append(mac_item_hex)
        # Format MAC as 00:11:22:33:44:AA
        parsed_mac = (':'.join(mac_list)).upper()
        # Format MAC OUI as 001122
        parsed_mac_oui = (''.join(mac_list[0:3])).upper()
        return (parsed_mac, parsed_mac_oui)

    # MAC OUI formatted '001122'
    def mac_oui(self, mac_oui_num: str) -> tuple:
        '''
        Get MAC OUI (vendor, type) based on an OUI number formatted as '00aaAA'

        Args:
            mac_oui_num (str): MAC OUI string eg 0011AA

        Returns:
            tuple: (Vendor, Type)
        '''
        try:
            return (self.mac_oui_data[mac_oui_num]['Vendor'], self.mac_oui_data[mac_oui_num]['Type'])
        except (NameError, KeyError):
            return False

### Generic ICMP Parsers ###


class icmp_parse(object):
    def __init__(self):
        # ICMP Types and corresponding Codes
        self.icmp_table = {
            0: {'Type': 'Echo Reply', 'Codes': {0: 'No Code'}},
            1: {'Type': 'Unassigned'},
            2: {'Type': 'Unassigned'},
            3: {
                'Type': 'Destination Unreachable',
                'Codes': {
                    0: 'Net Unreachable',
                    1: 'Host Unreachable',
                    2: 'Protocol Unreachable',
                    3: 'Port Unreachable',
                    4: 'Fragmentation Needed and Don\'t Fragment was Set',
                    5: 'Source Route Failed',
                    6: 'Destination Network Unknow',
                    7: 'Destination Host Unknow',
                    8: 'Source Host Isolated',
                    9: 'Communication with Destination Network is Administratively Prohibited',
                    10: 'Communication with Destination Host is Administratively Prohibited',
                    11: 'Destination Network Unreachable for Type of Service',
                    12: 'Destination Host Unreachable for Type of Service',
                    13: 'Communication Administratively Prohibited',
                    14: 'Host Precedence Violation',
                    15: 'Precedence cutoff in effect',
                }
            },
            4: {'Type': 'Source Quench', 'Codes': {0: 'No Code'}},
            5: {
                'Type': 'Redirect',
                'Codes': {
                    0: 'Redirect Datagram for the Network',
                    1: 'Redirect Datagram for the Host',
                    2: 'Redirect Datagram for the Type of Service and Network',
                    3: 'Redirect Datagram for the Type of Service and Host',
                }
            },
            6: {
                'Type': 'Alternate Host Address',
                'Codes': {
                    0: 'Alternate Address for Host',
                }
            },
            7: {'Type': 'Unassigned'},
            8: {'Type': 'Echo', 'Codes': {0: 'No Codes'}},
            9: {'TYpe': 'Router Advertisement', 'Codes': {0: 'No Codes'}},
            10: {'TYpe': 'Router Selection', 'Codes': {0: 'No Codes'}},
            11: {
                'Type': 'Time Exceeded',
                'Codes': {
                    0: 'Time to Live Exceeded in Transit',
                    1: 'Fragment Reassembly Time Exceeded',
                }
            },
            12: {
                'Type': 'Parameter Problem',
                'Codes': {
                    0: 'Pointer indicates the error',
                    1: 'Missing a Required Option',
                    2: 'Bad Length',
                }
            },
            13: {'Type': 'Timestamp', 'Codes': {0: 'No Codes'}},
            14: {'Type': 'Timestamp Reply', 'Codes': {0: 'No Codes'}},
            15: {'Type': 'Information Request', 'Codes': {0: 'No Codes'}},
            16: {'Type': 'Information Reply', 'Codes': {0: 'No Codes'}},
            17: {'Type': 'Address Mask Request', 'Codes': {0: 'No Codes'}},
            18: {'Type': 'Address Mask Reply', 'Codes': {0: 'No Codes'}},
            19: {'Type': 'Reserved'},
            20: {'Type': 'Reserved'},
            21: {'Type': 'Reserved'},
            22: {'Type': 'Reserved'},
            23: {'Type': 'Reserved'},
            24: {'Type': 'Reserved'},
            25: {'Type': 'Reserved'},
            26: {'Type': 'Reserved'},
            27: {'Type': 'Reserved'},
            28: {'Type': 'Reserved'},
            29: {'Type': 'Reserved'},
            30: {'Type': 'Reserved'},
            31: {'Type': 'Datagram Conversion Error'},
            32: {'Type': 'Mobile Host Redirect'},
            33: {'Type': 'IPv6 Where-Are-You'},
            34: {'Type': 'IPv6 I-Am-Here'},
            35: {'Type': 'Mobile Registration Request'},
            36: {'Type': 'Mobile Registration Reply'},
            37: {'Type': 'Domain Name Request'},
            38: {'Type': 'Domain Name Reply'},
            39: {'Type': 'SKIP'},
            40: {'Type': 'Photuris'},
        }

    # Parse human ICMP Type and Code from integers
    def icmp_human_type_code(self, icmp_reported: int) -> tuple:
        '''
            Parse ICMP integer to get the human ICMP Type and Code

            Args:
                icmp_reported (int): Exported ICMP code [(256 * ICMP Type) + ICMP Code]

            Returns:
                tuple: (ICMP Type: str, ICMP Code: str)
        '''
        icmp_num_type = icmp_reported // 256
        icmp_num_code = icmp_reported % 256

        try:
            icmp_parsed_type = self.icmp_table[icmp_num_type]['Type']
            try:
                icmp_parsed_code = self.icmp_table[icmp_num_type]['Codes'][icmp_num_code]
            except (NameError, KeyError):
                icmp_parsed_code = 'No Codes'

            return (icmp_parsed_type, icmp_parsed_code)
        except (NameError, KeyError):
            return (icmp_num_type, icmp_num_code)

    def icmp_num_type_code(self, icmp_reported: int) -> tuple:
        '''
        Parse ICMP integer to get the numeric ICMP Type and Code

        Args:
            icmp_reported (int): Exported ICMP code [(256 * ICMP Type) + ICMP Code]

        Returns:
            tuple: (ICMP Type: int, ICMP Code: int)
        '''
        icmp_num_type = icmp_reported // 256
        icmp_num_code = icmp_reported % 256
        return (icmp_num_type, icmp_num_code)

### Generic HTTP Parsers ###


class http_parse(object):
    def __init__(self):
        return

    def http_code_category(self, http_code: int) -> str:
        '''
        Reconcile an HTTP code to it's overall category eg 404 - Client Error

        Args:
            http_code (int): HTTP code eg 450

        Returns:
            str: HTTP Code Category eg 'Client Error'
        '''
        if http_code in range(100, 200):
            return 'Information'
        elif http_code in range(200, 300):
            return 'Success'
        elif http_code in range(300, 400):
            return 'Redirection'
        elif http_code in range(400, 500):
            return 'Client Error'
        elif http_code in range(500, 600):
            return 'Server Error'
        else:
            return 'Other'

    def http_code_parsed(self, http_code: int) -> str:
        '''
        Parse HTTP codes to HTTP code names

        Args:
            http_code (int): HTTP code number eg '404'

        Returns:
            str: Parsed HTTP code eg 'Not Found'
        '''
        if http_code == 200:
            return 'OK'
        elif http_code == 201:
            return 'Created'
        elif http_code == 202:
            return 'Accepted'
        elif http_code == 100:
            return 'Continue'
        elif http_code == 101:
            return 'Switching Protocols'
        elif http_code == 102:
            return 'Processing'
        elif http_code == 203:
            return 'Non-Authoritative Information'
        elif http_code == 204:
            return 'No Content'
        elif http_code == 205:
            return 'Reset Content'
        elif http_code == 206:
            return 'Partial Content'
        elif http_code == 207:
            return 'Multi-Status'
        elif http_code == 208:
            return 'Alread Reported'
        elif http_code == 226:
            return 'IM Used'
        elif http_code == 300:
            return 'Multiple Choices'
        elif http_code == 301:
            return 'Moved Permanently'
        elif http_code == 302:
            return 'Found'
        elif http_code == 303:
            return 'See Other'
        elif http_code == 304:
            return 'Not Modified'
        elif http_code == 305:
            return 'Use Proxy'
        elif http_code == 306:
            return 'Switch Proxy'
        elif http_code == 307:
            return 'Temporary Redirect'
        elif http_code == 308:
            return 'Permanent Redirect'
        elif http_code == 400:
            return 'Bad Request'
        elif http_code == 401:
            return 'Unauthorized'
        elif http_code == 402:
            return 'Payment Required'
        elif http_code == 403:
            return 'Forbidden'
        elif http_code == 404:
            return 'Not Found'
        elif http_code == 405:
            return 'Method Not Allowed'
        elif http_code == 406:
            return 'Not Acceptable'
        elif http_code == 407:
            return 'Proxy Authentication Required'
        elif http_code == 408:
            return 'Request Time-Out'
        elif http_code == 409:
            return 'Conflict'
        elif http_code == 410:
            return 'Gone'
        elif http_code == 411:
            return 'Length Required'
        elif http_code == 412:
            return 'Precondition Failed'
        elif http_code == 413:
            return 'Payload Too Large'
        elif http_code == 414:
            return 'URI Too Long'
        elif http_code == 415:
            return 'Unsupported Media Type'
        elif http_code == 416:
            return 'Range Not Satisfiable'
        elif http_code == 417:
            return 'Expection Failed'
        elif http_code == 418:
            return 'Teapot'
        elif http_code == 421:
            return 'Misdirected Request'
        elif http_code == 422:
            return 'Unprocessable Entity'
        elif http_code == 423:
            return 'Locked'
        elif http_code == 424:
            return 'Failed Dependency'
        elif http_code == 426:
            return 'Upgrade Required'
        elif http_code == 428:
            return 'Precondition Required'
        elif http_code == 429:
            return 'Too Many Requests'
        elif http_code == 431:
            return 'Rquest Header Fields Too Large'
        elif http_code == 451:
            return 'Unavailable For Legal Reasons'
        elif http_code == 500:
            return 'Internal Server Error'
        elif http_code == 501:
            return 'Not Implemented'
        elif http_code == 502:
            return 'Bad Gateway'
        elif http_code == 503:
            return 'Service Unavailable'
        elif http_code == 504:
            return 'Gateway Time-Out'
        elif http_code == 505:
            return 'HTTP Version Not Supported'
        elif http_code == 506:
            return 'Variant Also Negotiates'
        elif http_code == 507:
            return 'Insuficient Storage'
        elif http_code == 508:
            return 'Loop Detected'
        elif http_code == 510:
            return 'Not Extended'
        elif http_code == 511:
            return 'Network Authentication Required'
        else:
            return 'Other'

### Netflow v9 Parsers ###


class netflowv9_parse(object):
    import struct
    from struct import unpack
    from collections import OrderedDict
    from field_types import v9_fields

    def __init__(self):
        return

    # Parsing template flowset
    def template_flowset_parse(self, packed_data: struct, sensor: str, pointer: int, length: int) -> dict:
        '''
        Unpack a Netflow v9 template

        Args:
            packed_data (struct): Packed data
            sensor (str): Netflow v9 sensor
            pointer (int): Current unpack location
            length (int): Length of data to unpack

        Returns:
            dict[Hashed ID]: {Sensor: str, Template ID: int, Length: int, Type: int, Definitions: dict}
        '''
        cache = {}
        while pointer < length:
            (template_id, template_field_count) = self.unpack(
                '!HH', packed_data[pointer:pointer + 4])
            pointer += 4  # Advance the field

            hashed_id = hash(str(sensor) + str(template_id))
            cache[hashed_id] = {}
            cache[hashed_id]['Sensor'] = str(sensor)
            cache[hashed_id]['Template_ID'] = template_id
            cache[hashed_id]['Length'] = template_field_count
            cache[hashed_id]['Type'] = 'Flow Data'
            cache[hashed_id]['Definitions'] = self.OrderedDict()

            # Iterate through each line in the template
            for _ in range(0, template_field_count):
                (element, element_length) = self.unpack(
                    '!HH', packed_data[pointer:pointer + 4])
                if element in self.v9_fields:
                    cache[hashed_id]['Definitions'][element] = element_length
                pointer += 4
        return cache

    # Parsing option template
    def option_template_parse(self, packed_data: struct, sensor: str, pointer: int) -> dict:
        '''
        Unpack a Netflow v9 option template

        Args:
            packed_data (struct): Packed data
            sensor (str): Netflow v9 sensor
            pointer (int): Current unpack location

        Returns:
            dict[Hashed ID]: {Sensor: str, Template ID: int, Type: str, Scope Fields: dict, Option Fields: dict}
        '''
        (option_template_id, option_scope_length, option_length) = self.unpack(
            '!HHH', packed_data[pointer:pointer + 6])
        pointer += 6

        cache = {}
        # Hash for individual and template ID
        hashed_id = hash(str(sensor) + str(option_template_id))
        cache[hashed_id] = {}
        cache[hashed_id]['Sensor'] = str(sensor)
        cache[hashed_id]['Template_ID'] = option_template_id
        cache[hashed_id]['Type'] = 'Options Template'
        cache[hashed_id]['Scope Fields'] = self.OrderedDict()
        cache[hashed_id]['Option Fields'] = self.OrderedDict()

        for x in range(pointer, pointer + option_scope_length, 4):
            (scope_field_type, scope_field_length) = self.unpack(
                '!HH', packed_data[x:x + 4])
            cache[hashed_id]['Scope Fields'][scope_field_type] = scope_field_length

        pointer += option_length
        return cache

### Protocol and Port Parsers ###


class ports_and_protocols(object):
    # Field types, defined ports, etc
    pass
