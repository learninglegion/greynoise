# Script to run a set of IPs, ASN, or other network format through
# greynoise and then digCUST to find IPs that need to be reviewed
# for malicious intent.

# current requirements:
# file with IPs (IPv4), ASN(e.g. AS7029), or other IPv4 network format
# strict format requirement (else errors), one entry per line.
# filename iplist.txt in same dir as program

# Take in IP, IPs, network, or ASN format

# Review IPs for dynamic ranges
# or preemptively remove dynamic ranges

# Run IPs through greynoise

# Output results to results.csv in user friendly format

# Refactoring - functions/objectify, exceptions, entry sanitization
#######################################################################

#test
 
# For testing purposes, run OS/dig 'commands' on IPs/networks
# and save to output file

import dns
from dns import resolver, reversename
import ipaddress
import requests

# gnapi_dict = {'ip': '8.8.8.8', 'noise': False, 'riot': True,\
#  'classification': 'benign', 'name': 'Google Public DNS',\
#  'link': 'https://viz.greynoise.io/riot/8.8.8.8',\
#  'last_seen': '2021-06-14', 'message': 'Success'}



#Prep results.csv column headers
results = open("results.csv", "a")
results.write(f"Entry, IP checked, PTR, GN_noise, GN_riot, GN_class,\
 GN_name, GN_link, GN_lastseen, GN_message\n")
results.close

# open iplist.txt file and read lines
with open('iplist.txt', 'r') as file1:
    for line in file1:
        entry = line.strip()

# Validate IP and set is_ip = True if valid IP
        is_ip = False
        try:
            ipcheck = ipaddress.ip_address(entry)
        except ValueError:
            pass
        else:
            is_ip = True

# Assume string with '/' is subnet, extrapolate IPs, and lookup PTR
# Needs more validity work
        if "/" in line:
            subnet = entry
            sub_list = [str(ip) for ip in\
            ipaddress.IPv4Network(subnet)]
            print(f"{subnet} is a subnet with {len(sub_list)} IPs.")
            for sub_ip in sub_list:
                print(f"Researching {sub_ip}")
                sub_rev = reversename.from_address(sub_ip)
                try:
                    sub_ptr = str(resolver.resolve(sub_rev, "PTR")[0])
                except dns.resolver.NXDOMAIN:
                    sub_ptr = 'No PTR'
                gnapi_dict = {'ip': '8.8.8.8', 'noise': False, 'riot': True,\
 'classification': 'benign', 'name': 'Google Public DNS',\
 'link': 'https://viz.greynoise.io/riot/8.8.8.8',\
 'last_seen': '2021-06-14', 'message': 'Success'}
                del gnapi_dict['ip']
                with open('results.csv', 'a') as results:
                    results.write(f"{entry},{sub_ip},{sub_ptr},")
                    for key, value in gnapi_dict.items(): 
                        results.write(f"{value},")
                    results.write("\n")

                    
# Assume string with upper/lowercase ASN or AS is ASN and look up
# netblocks. Needs more validity work and netblock breakdown
# Possibly add ASN name lookup functionality
# Code exception for 404s for shadowserver queries
        elif "ASN" in line or "asn" in line or\
        "AS" in line or "as" in entry:
            asn = entry
            print(f"{asn} is an ASN. Querying shadowserver.org...")
# Parse out ASN
            numeric_filter = filter(str.isdigit, asn)
            as_number = "".join(numeric_filter)
# Query Shadowserver for ASN networks
# ToDo - check for site 200 response before running actual query
            aslookup_url =\
            f"https://api.shadowserver.org/net/asn?prefix={as_number}"
            aslookup_res = requests.get(aslookup_url)
            as_net_list = aslookup_res.json()
            print(f"Networks/subnets in {asn} are:")
            for as_net in as_net_list:
                print(as_net)
# LOTS of IPs to be analyzed from ASN netblocks
# Commented during dev for quick test purposes
            for as_net in as_net_list:
                as_sub = [str(ip) for ip in\
                ipaddress.IPv4Network(as_net)]
                print(f"Researching IPs in {as_net}.\
                \nThis may take a while...") 
                for as_ip in as_sub:
                    print(f"Researching {as_ip}")
                    as_rev = reversename.from_address(as_ip)
                    try:
                        as_ptr =\
                        str(resolver.resolve(as_rev, "PTR")[0])
                    except dns.resolver.NXDOMAIN:
                        as_ptr = 'No PTR'
                    gnapi_dict = {'ip': '8.8.8.8', 'noise': False, 'riot': True,\
 'classification': 'benign', 'name': 'Google Public DNS',\
 'link': 'https://viz.greynoise.io/riot/8.8.8.8',\
 'last_seen': '2021-06-14', 'message': 'Success'}
                    del gnapi_dict['ip']
                    with open('results.csv', 'a') as results:
                        results.write(f"{entry},{as_ip},{as_ptr},")
                        for key, value in gnapi_dict.items(): 
                            results.write(f"{value},")
                        results.write("\n")    

# If IP, do reverse lookup
        elif is_ip == True:
            ip = entry
            print(f"Just an IP here. Researching {ip}")
            ip_rev = reversename.from_address(ip)
            try:
                ip_ptr = str(resolver.resolve(ip_rev, "PTR")[0])
            except dns.resolver.NXDOMAIN:
                ip_ptr = 'No PTR'
            # gnapi_url =\
            # f"https://api.greynoise.io/v3/community/{ip}"
            # gnapi_res = requests.get(gnapi_url)
            # gnapi_dict = gnapi_res.json()
            gnapi_dict = {'ip': '8.8.8.8', 'noise': False, 'riot': True,\
 'classification': 'benign', 'name': 'Google Public DNS',\
 'link': 'https://viz.greynoise.io/riot/8.8.8.8',\
 'last_seen': '2021-06-14', 'message': 'Success'}
            del gnapi_dict['ip']
            with open('results.csv', 'a+') as results:
                results.write(f"{entry},{ip},{ip_ptr},")
                for key, value in gnapi_dict.items(): 
                    results.write(f"{value},")
                results.write("\n")
            
# If not IP, subnet, or ASN return invalid input error
        else:
            print(f"{entry} appears to be invalid.")
            results = open("results.csv", "a")
            results.write(f"{entry},Invalid entry\n")
            results.close

print("Research complete.")
print("Results can be found in ./results.csv ")





