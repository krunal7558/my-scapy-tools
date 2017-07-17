################################################################################
# Script Name: pcap2asn.py
# Author : Krunal Shah
# Written and tested with Python2.7.12
# Last update : 17 July 2017
# Got DDoS? Did you defend ? Great. Want to look back where it was originated from? Or just want to find out
# captured traffic's Source or Destination AS numbers?
# This Python script is developed to parse pcap file and extract its source or destinatipn IP address 
# and find out its asn,contry_code, ASN description using iptoasn REST API and dumps results in csv file 
# for further analysis.
################################################################################
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

#!/usr/bin/python
import requests, logging, argparse, csv, json
import ipaddr as ipaddress
# Import scapy modules here
from scapy.plist import PacketList
from scapy.layers import *
from scapy.all import rdpcap, IP

# iptoasn base URL
ip2asn_url = "https://api.iptoasn.com/v1/as/ip/"

if __name__ == '__main__':
    # Parse and validate arguments and print usage information
    parser = argparse.ArgumentParser(prog='pcap2asn.py', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--i', type=str, help='Input pcap file name')
    parser.add_argument('--s', help='Evalute source IP', action='store_true')
    parser.add_argument('--d', help='Evalute destination IP', action='store_true')
    parser.add_argument('--o', type=str, help='Output csv file name with ASN info')
    parser.add_argument('--D', help='Enable DEBUG mode', action='store_true')
    args = vars(parser.parse_args())   # Parse Arguments
    # Set logging level to ERROR,DEBUG or INFO here
    if args['D']:
        logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.ERROR)
    if args['i'] is None:
        args['i'] = raw_input("Enter pcap file name: ")
    if args['o'] is None:
        args['o'] = raw_input("Enter output file name: ")
    pkts = rdpcap(args['i'])
    try:
        with open(args['o'], 'w') as fh:
            fieldnames = ['ip', 'as_number', 'country_code', 'description']
            csvfh = csv.DictWriter(fh, fieldnames=fieldnames)
            csvfh.writeheader() # Write first row with field names
            for pkt in pkts:   # Iterate over each packets in pcap file
                if args['s']:  # If source IP (--s) argument is present 
                    ip = pkt.getlayer(IP).src
                elif args['d']: # if destination IP (--d) argument is present
                    ip = pkt.getlayer(IP).dst
                logging.debug("IP address: {}".format(ip))
                ip_addr = ipaddress.IPv4Address(ip) # Convert in to IPv4Address object
                if not (ip_addr.is_private or ip_addr.is_multicast or ip_addr.is_loopback or ip_addr.is_reserved):
                    response = requests.get(ip2asn_url+ip).json()
                    try:
                        csvfh.writerow({'ip':ip, 'as_number':response["as_number"], 'country_code':response["as_country_code"], 'description':response["as_description"]})
                        logging.debug("{},{},{},{}".format(ip, response["as_number"], response["as_country_code"], response["as_description"]))
                    except:
                        csvfh.writerow({'ip':ip, 'as_number':"unknown", 'country_code':"unknown", 'description':"unknown"})
                        logging.debug("{},{},{},{}".format(ip, "unknown", "unknown", "unknown"))
                else:
                    csvfh.writerow({'ip':ip, 'as_number':"NA", 'country_code':"NA", 'description':"NA"})
    except Exception as e:
        logging.error(e)