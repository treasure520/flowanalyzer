# Copyright (c) 2017, Manito Networks, LLC
# All rights reserved.

### Imports ###
import time, datetime, socket, struct, sys, os, json, socket, collections, itertools, logging, logging.handlers, getopt
#from struct import *
#from elasticsearch importo Elasticsearch, helpers
from IPy import IP

# Parsing functions
from parser_modules import mac_address, icmp_parse, ip_parse, netflowv9_parse, int_parse, ports_and_protocols, name_lookups

# Fields types, defined ports, etc
from field_types import v9_fields
from netflow_options import *

### Get the command line arguments ###
try:
    arguments = getopt.getopt(sys.argv[1:], 'hl:', ['--help', 'log='])

    for option_set in arguments:
        for opt, arg in option_set:
            if opt in ('-l', '--log'):
                arg = arg.upper()
                if arg in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']:
                    log_level = arg
            elif opt in ('-h', '--help'):
                with open('./help.txt') as help_file:
                    print(help_file.read())
                sys.exit()
            else:
                pass
except Exception:
    sys.exit('Unsupported or badly formed options, see -h for available arguments.')

### Logging Level ###
# Per https://docs.python.org/2/howto/logging.html
try:
    log_level
except NameError:
    log_level = 'WARNING'

logging.basicConfig(level=str(logging))
logging.warning('Log level set to {} - OK'.format(log_level))

### DNS Lookups ###
#
# Reverse lookups
try:
    if dns is False:
        logging.warning('DNS reverse lookups disabled - DISABLED')
    elif dns is True:
        logging.warning('DNS reverse lookups enabled - OK')
    else:
        logging.warning('DNS enable option incorrectly set - DISABLING')
        dns = False
except:
    logging.warning('DNS enable option not set - DISABLING')
    dns = False

# RFC-1918 reverse lookups
try:
    if lookup_internal is False:
        logging.warning('DNS local IP reverse lookups disabled - DISABLED')
    elif lookup_internal is True:
        logging.warning('DNS local IP reverse lookups enabled - OK')
    else:
        logging.warning('DNS local IP reverse lookups incorrectly set - DISABLING')
        lookup_internal = False
except:
    logging.warning('DNS local IP reverse lookups not set - DISABLING')
    lookup_internal = False

# Check if the Netflow v9 port is specified
try:
    netflow_v9_port
except NameError:
    netflow_v9_port = 9995
    logging.warning('Netflow v9 port not set in netflow_options.py, defaulting to {} - OK'.format(netflow_v9_port))

# Set up socket listener
try:
    netflow_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    netflow_sock.bind(('0.0.0.0', netflow_v9_port))
    logging.warning('Bound to port {} - OK'.format(netflow_v9_port))
except ValueError as socket_error:
    logging.critical('Could not open or bind a socket on port {} - FAIL'.format(netflow_v9_port))
    logging.critical(str(socket_error))
    sys.exit()

# Spin up ES instance
# es = Elasticsearch([elasticsearch_host])

# Stage individual flow
global flow_index
flow_index = {}
flow_index['_source'] = {}

# Stage multiple flows for the bulk Elasticsearch API index operation
global flow_dic
flow_dic = []

# Cache the Netflow v9 templates in received order to decode the data flows. ORDER MATTERS FOR TEMPLATES.
global template_list
template_list = {}

# Record counter for Elasticsearch bulk API upload trigger
record_num = 0

### Netflow v9 Collector ###
if __name__ == '__main__':
    # ICMP Types and Codes
    icmp_parser = icmp_parse()
    # Unpacking and parsing IPv4 and IPv6b Addresses
    ip_parser = ip_parse()
    # Unpacking and parsing MAC addresses and OUIs
    mac = mac_address()
    # Parsing Netflow v9 structures
    netflow_v9_parser = netflowv9_parse()
    # Unpacking and parsing integers
    int_un = int_parse()
    # Ports and Protocols
    ports_protocols_parser = ports_and_protocols()
    # DNS reverse lookups
    name_lookup = name_lookups()

    # Continually collect packets
    while True:
        # Tracking locaation in the packet
        pointer = 0
        # For debug purpose only
        flow_counter = 0

        # Listen for packets inbound
        flow_packet_contents, sensor_address = netflow_sock.recvfrom(65565)

        ### Unpack the flow packet header ###
        try:
            logging.info('Unpacking header from {}'.format(sensor_address[0]))

            # Flow header attributes cache
            packet = {}

            # Unpack header
            (
                packet['netflow_version'],
                packet['total_flow_count'],
                packet['sys_uptime'],
                packet['unix_secs'],
                packet['sequence_number'],
                packet['source_id'],
            ) = struct.unpack('!HHLLLL', flow_packet_contents[0:20])

            packet['Sensor'] = str(sensor_address[0])
            # Move past the packet header
            pointer += 20

            logging.info(str(packet))
        except Exception as flow_header_error:
            # Something went wrong unpacking the header, bail out
            logging.warning('Failed unpacking flow header from {} - {}'.format(sensor_address[0], flow_header_error))
            continue

        # Check Netflow version
        if int(packet['netflow_version']) != 9:
            logging.warning('Received a non-Netflow v9 packet from {} - SKIPPING PACKET'.format(sensor_address[0]))
            # Bail out
            continue

        # Iterate through all flows in the packet
        while True:
            # Unpack flow set ID and the length
            try:
                (flow_set_id, flow_set_length) = struct.unpack('!HH', flow_packet_contents[pointer:pointer + 4])
                logging.info('Found flow ID {}, length {} at {}'.format(flow_set_id, flow_set_length, pointer))
            except:
                logging.info('Out of bytes to unpack, stopping - OK')
                break

            # Advance past the flow ID and Length
            pointer += 4

            logging.info('Finished, position {}'.format(pointer))

            if flow_set_id == 0:
                # Template flowset
                logging.info('Unpacking template flowset {}, pointer {}'.format(flow_set_id, pointer))

                # Parse tempates
                parsed_templates = netflow_v9_parser.template_flowset_parse(
                    flow_packet_contents,
                    sensor_address[0],
                    pointer,
                    flow_set_length
                )
                # Add the new template(s) to the working template list
                template_list.update(parsed_templates)

                logging.debug(str(parsed_templates))

                # Advance to the end of the flow
                pointer = (flow_set_length + pointer) - 4
                logging.info('Finished, position {}'.format(pointer))

                flow_counter += 1
                record_num += 1
            elif flow_set_id == 1:
                # Options template set
                logging.warning('Unpacking Options template set, positionn {}'.format(pointer))

                option_templates = netflow_v9_parser.option_template_parse(flow_packet_contents, sensor_address[0], pointer)
                # Add the new Option template(s) to the working template list
                template_list.update(option_set)

                logging.debug(str(template_list))
                pointer = (flow_set_length + pointer) - 4
                logging.info('Finished, position {}'.format(pointer))

                flow_counter += 1
                record_num += 1
            elif flow_set_id > 255:
                # Flow data set
                logging.info('Unpacking data set {}, position {}'.format(flow_set_id, pointer))

                hashed_id = hash(str(sensor_address[0]) + str(flow_set_id))

                if hashed_id not in template_list:
                    logging.warning('Missing template for set {} fromo {}, sequence {} - DROPPING'.format(
                        flow_set_id,
                        sensor_address[0],
                        packet['sequence_number'],
                    ))

                    # Advance to the end of the flow
                    pointer = (flow_set_length + pointer) - 4
                    logging.info('Finished, position {}'.format(pointer))
                    continue

                data_position = pointer

                # Get the current UTC time for the flows
                now = datetime.datetime.utcnow()

                if template_list[hashed_id]['Type'] == 'Flow Data':
                    # Cache the flow data, to be append to flow dic[]
                    flow_index = {
                        '_index': str('flow-{}'.format(now.strftime('%Y-%m-%d'))),
                        '_type': 'Flow',
                        '_source': {
                            'Sensor': sensor_address[0],
                            'Sequence': packet['sequence_number'],
                            'Source ID': packet['source_id'],
                            'Time': '{}.{:03}Z'.format(now.strftime('%Y-%m-%dT%H:%M:%S'), int(now.microsecond/1000))
                        }
                    }

                    flow_counter += 1
                    record_num += 1

                    # Note the type
                    flow_index['_source']['Flow Type'] = 'Netflow v9'

                    logging.info('Data flow number {}, set ID {} from {}'.format(flow_counter, flow_set_id, sensor_address[0]))

                    ### Iterate through the ordered template ###
                    for template_key, field_size in template_list[hashed_id]['Definitions'].iteritems():
                        # Checkk if the template key is defined in the Netflow v9 standard fields
                        #
                        # Skip this field if it's not defined, even though it's in the template
                        try:
                            v9_fields[template_key]
                        except KeyError:
                            logging.info('Skipping undefined field (template_key, field_size - ({}, {})'.format(template_key, field_size))
                            data_position += field_size
                            # Skip this undefined field
                            continue

                        if v9_fields[template_key]['Type'] == 'IPv4':
                            ### IPv4 field ###
                            flow_payload = ip_parser.parse_ipv4(flow_packet_contents, data_position, field_size)
                            flow_index['_source']['IP Protocol Version'] = 4
                        elif v9_fields[template_key]['Type'] == 'IPv6':
                            ### IPv6 field ###
                            flow_payload = ip_parser.parse_ipv6(flow_packet_contents, data_position, field_size)
                            flow_index['_source']['IP Protocol Version'] = 6
                        elif v9_fields[template_key]['Type'] == 'Integer':
                            ### Integer field ###
                            # Unpack the integer
                            flow_payload = int_un.integer_unpack(flow_packet_contents, data_position, field_size)

                            if template_key == 4:
                                # IANA protocol number in case the customer wants to sort by protocol number
                                flow_index['_source']['Protocol Number'] = flow_payload
                            elif template_key in [32, 139]:
                                # Do the special calculations for ICMP Code and Type (% operator)
                                num_icmp = icmp_parser.icmp_num_type_code(flow_payload)
                                flow_index['_source']['ICMP Type'] = num_icmp[0]
                                flow_index['_source']['ICMP Type'] = num_icmp[1]

                                human_icmp = icmp_parser.icmp_human_type_code(flow_payload)
                                flow_index['_source']['ICMP Parsed Type'] = human_icmp[0]
                                flow_index['_source']['ICMP Parsed Code'] = human_icmp[1]
                            else:
                                # Not a specially parsed field, just ignore
                                pass
                        elif v9_fields[template_key]['Type'] == 'MAC':
                            ### MAC Address field ###
                            # Parse MAC
                            parsed_mac = mac.mac_packed_parse(flow_packet_contents, data_position, field_size)
                            # Parsed MAC address
                            flow_payload = parsed_mac[0]

                            ### MAC Address OUIs ###
                            if template_key == 56:
                                # Incoming Source MAC
                                flow_index['_source']['Incoming Source MAC OUI'] = parsed_mac[1]
                            elif template_key == 57:
                                # Outgoing Destination MAC
                                flow_index['_source']['Outgoing Destination MAC OUI'] = parsed_mac[1]
                            elif template_key == 80:
                                # Incoming Destination MAC
                                flow_index['_source']['Incoming Destination MAC OUI'] = parsed_mac[1]
                            elif template_key == 81:
                                # Outgoing Source MAC
                                flow_index['_source']['Outgoing Source MAC OUI'] = parsed_mac[1]
                            elif template_key == 365:
                                # Station MAC Address
                                flow_index['_source']['Station MAC Address OUI'] = parsed_mac[1]
                            elif template_key == 367:
                                # WTP MAC Address
                                flow_index['_source']['WTP MAC Address OUI'] = parsed_mac[1]
                            elif template_key == 414:
                                # Dot1q Customer Source MAC Address
                                flow_index['_source']['Dot1q Customer Source MAC Address OUI'] = parsed_mac[1]
                            elif template_key == 415:
                                # Dot1q Customer Destination MAC Address
                                flow_index['_source']['Dot1q Customer Destination MAC Address OUI'] = parsed_mac[1]
                            else:
                                # Not a special MAC field
                                pass
                        else:
                            # Somthing Else ###
                            logging.warning('Unsupported field number {}, size {} from {} in sequence {}'.format(
                                template_key,
                                field_size,
                                sensor_address[0],
                                packet['sequence_number'],
                            ))

                            data_position += field_size
                            # Bail out of this field, either undefined or proprietary - skip
                            continue

                        ### Special parsed fields with pre-defined values ###
                        if 'Options' in v9_fields[template_key]:
                            # Integer fields with pre-defined values in the v9 standard
                            try:
                                flow_index['_source'][v9_fields[template_key]['Index ID']] = v9_fields[template_key]['Options'][int(flow_payload)]
                            except Exception as option_warning:
                                logging.warning('Failed to parse human option, template {}, option key {} from {} - USING INTEGER VALUE'.format(
                                    template_key,
                                    str(flow_payload),
                                    str(sensor_address[0]),
                                ))
                                flow_index['_source'][v9_fields[template_key]['Index ID']] = flow_payload
                        else:
                            ### Typical field with human-friendly name ###
                            flow_index['_source'][v9_fields[template_key]['Index ID']] = flow_payload

                        # Move the byte position the number of bytes in the field we just parsed
                        data_position += field_size

                    ### Traffic and Traffic Category tagging ###
                    #
                    if int(flow_index['_source']['Protocol Number']) in (6, 17, 33, 132):
                        # Transport protocols e.g. TCP, UDP, etc
                        traffic_tags = ports_protocols_parser.port_traffic_classifier(
                            flow_index['_source']['Source Port'],
                            flow_index['_source']['Destination Port'],
                        )
                        flow_index['_source']['Traffic'] = traffic_tags['Traffic']
                        flow_index['_source']['Traffic Category'] = traffic_tags['Traffic Category']
                    else:
                        # Non-transport protocols e.g. OSPF, VRRP, etc
                        try:
                            flow_index['_source']['Traffic Category'] = ports_protocols_parser.protocol_traffic_category(
                                flow_index['_source']['Protocol Number']
                            )
                        except:
                            flow_index['_source']['Traffic Category'] = 'Uncategorized'


                    ### DNS Domain and FQDN tagging ###
                    if dns is True:
                        # Source DNS
                        if 'IPv4 Source' in flow_index['_source']:
                            source_lookups = name_lookup.ip_names(4, flow_index['_source']['IPv4 Source'])
                        elif 'IPv6 Source' in flow_index['_source']:
                            source_lookups = name_lookup.ip_names(6, flow_index['_source']['IPv6 Source'])

                        flow_index['_source']['Source FQDN'] = source_lookups['FQDN']
                        flow_index['_source']['Source Domain'] = source_lookups['Domain']

                        # Destination DNS
                        if 'IPv4 Destination' in flow_index['_source']:
                            destination_lookups = name_lookup.ip_names(4, flow_index['_source']['IPv4 Destination'])
                        elif 'IPv6 Destination' in flow_index['_source']:
                            destination_lookups = name_lookup.ip_names(6, flow_index['_source']['IPv6 Destination'])

                        flow_index['_source']['Destination FQDN'] = destination_lookups['FQDN']
                        flow_index['_source']['Destination Domain'] = destination_lookups['Domain']

                        # Content
                        src_dst_categories = [source_lookups['Content'], destination_lookups['Content']]

                        try:
                            # Pick unique domain Content != 'Uncategorized'
                            unique_content = [category for category in src_dst_categories if category != 'Uncategorized']
                            flow_index['_source']['Content'] = unique_content[0]
                        except:
                            # No unique domain Content
                            flow_index['_source']['Content'] = 'Uncategorized'

                    ## Append flow to the cache ###
                    flow_dic.append(flow_index)
                    logging.debug(str(flow_index))
                    logging.info('Ending data flow {}'.format(str(flow_counter)))

                elif template_list[hashed_id]['Type'] == 'Options Template':
                    ### Options Template ###
                    flow_counter += 1
                    record_num += 1

                    logging.info('Creating Netflow v9 Options flow number {}, set ID {} from {}'.format(
                        flow_counter,
                        flow_set_length,
                        str(sensor_address[0]),
                    ))
                    # Note the type
                    flow_index['_source']['Flow Type'] = 'Netflow v9 Options'

                    for scope_field in template_list[hashed_id]['Scope Fields']:
                        logging.debug(str(scope_field))

                    for option_field in template_list[hashed_id]['Option Fields']:
                        logging.debug(str(option_field))

                    logging.info('Ending Netflow v9 Options flow {}'.format(flow_counter))
                else:
                    pass

                # Advance to the end the flow
                pointer = (flow_set_length + pointer) - 4
                logging.info('Finished set {}, position {}'.format(flow_set_id, pointer))
            else:
                # Rcvd a flow set ID we haven't accounted for
                logging.warning('Unknown flow {} from {} -FAIL'.format(flow_set_id, str(sensor_address[0])))
                pointer = (flow_set_length + pointer) - 4
                flow_counter += 1
                continue
        packet['Reported Flow Count'] = flow_counter
        logging.debug('Cached templates: {}'.format(str(template_list)))

        # Have enough flows to do a bulk index to Elasticsearch
        if record_num >= bulk_insert_count:
            # Perform the bulk upload to the index
            try:
                #helps.bulk(es, flow_dic)
                logging.info('{} flow(s) uploaded to Elasticsearch - OK'.format(record_num))
            except ValueError as bulk_index_error:
                logging.critical(bulk_index_error)
                logging.critical('{} flow(s) DROPPED, unable to index flows - FAIL'.format(record_num))

            # Empty flow_dic
            flow_dic = []
            # Reset the record counter
            record_num = 0




















