#!/usr/bin/python

###############################################################################
# Script Name: pcap2asn.py
# Author : Krunal Shah
# Written and tested with Python2.7.12
# This Python script is developed to parse pcap file and extract its source or 
# destinatipn IP address and find out its asn,contry_code, ASN description 
# using bgpview.io REST API and dumps results in csv file 
# for further analysis.
###############################################################################
'''
$python pcap2asn.py --i pcapdata_f1528556.pcap --s --o pcap2asn-report.csv
$python pcap2asn.py --help

usage: pcap2asn.py [-h] [--i I] [--s] [--d] [--o O]

optional arguments:
  -h, --help  show this help message and exit
  --i I       Input pcap file name (default: None)
  --s         Evalute source IP (default: False)
  --d         Evalute destination IP (default: False)
  --o O       Output csv file name with ASN info (default: None)
'''

import requests, logging, argparse, csv, json
from netaddr import *
# Import scapy modules here
from scapy.plist import PacketList
from scapy.layers import *
from scapy.all import rdpcap, IP

# iptoasn base URL
ip2asn_url = "https://api.iptoasn.com/v1/as/ip/"
# bgpview URL
bgpview_url = "https://api.bgpview.io/ip/"

if __name__ == '__main__':
    # Parse and validate arguments and print usage information
    parser = argparse.ArgumentParser(prog='pcap2asn.py', 
                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--i', type=str, help='Input pcap file name')
    parser.add_argument('--s', help='Evalute source IP', action='store_true')
    parser.add_argument('--d', 
                  help='Evalute destination IP (Default if Nothing specified)',
                  action='store_true')
    parser.add_argument('--o', type=str, 
                                     help='Output csv file name with ASN info')
    parser.add_argument('--D', help='Enable DEBUG mode', action='store_true')
    args = vars(parser.parse_args())   # Parse Arguments
    # Set logging level to ERROR,DEBUG or INFO here
    if args['D']:
        logging.basicConfig(format='%(levelname)s:%(message)s', 
                                                           level=logging.DEBUG)
    else:
        logging.basicConfig(format='%(levelname)s:%(message)s', 
                                                           level=logging.ERROR)
    if args['i'] is None:
        args['i'] = raw_input("Enter pcap file name: ")
    if args['o'] is None:
        args['o'] = raw_input("Enter output file name: ")
    # Scapy function call to open pcap file and create 
    # PacketList object to iterate over    
    pkts = rdpcap(args['i']) 
    try:
        with open(args['o'], 'w') as fh:
            fieldnames = ['ip','prefix', 'as_number', 
                                                'country_code', 'description']
            csvfh = csv.DictWriter(fh, fieldnames=fieldnames)
            csvfh.writeheader() # Write first row with field names
            # Iterate over each packets in pcap file (PacketList object)
            for pkt in pkts:    
                if args['s']:  # If source IP (--s) argument is present 
                    ip = pkt.getlayer(IP).src
                else: # by default pick destination address. 
                    ip = pkt.getlayer(IP).dst
                logging.debug("IP address: {}".format(ip))
                ip_addr = IPAddress(ip) # Convert in to IPv4Address object
                # check to see if IP from IANA reserved range
                if not (ip_addr.is_private() or ip_addr.is_multicast() 
                            or ip_addr.is_loopback() or ip_addr.is_reserved()):
                    # Make iptoasn API call to get response in JSON and map it 
                    # to a dictionary object
                    response = requests.get(bgpview_url+ip).json() 
                    try:
                        prefixes = response['data']['prefixes']
                        for prefix in prefixes:
                            csvfh.writerow({'ip':ip, 'prefix':str(prefix['prefix']), 
                                       'as_number':prefix['asn']['asn'], 
                                       'country_code':prefix['asn']['country_code'],
                                       'description':prefix['asn']["description"]})
                            logging.debug("{},{},{},{}".format(ip,
                                          prefix['asn']['asn'],
                                          prefix['asn']['country_code'],
                                          prefix['asn']["description"]))
                    except:
                        csvfh.writerow({'ip':ip, 'as_number':"unknown", 
                                 'country_code':"unknown", 'description':"unknown"})
                        logging.debug("{},{},{},{}".format(ip, 
                                   "unknown", "unknown", "unknown"))
                else:
                    csvfh.writerow({'ip':ip, 'as_number':"NA", 
                                       'country_code':"NA", 'description':"NA"})
    except Exception as e:  # Catching too generic exception but thats OK
        logging.error(e)
