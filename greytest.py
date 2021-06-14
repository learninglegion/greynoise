import requests

# ip = "8.8.8.8"
# gnapi_url =\
# f"https://api.greynoise.io/v3/community/{ip}"
# gnapi_res = requests.get(gnapi_url)
# gnapi_dict = gnapi_res.json()

with open('testGN.txt', 'a') as f:
    f.write("GN_IP, GN_noise, GN_riot, GN_class,\
GN_name, GN_link, GN_lastseen, GN_message\n")
# results = open("testGN.txt", "a+")
# results.write("GN_IP, GN_noise, GN_riot, GN_class,\
# GN_name, GN_link, GN_lastseen, GN_message\n")
# results.close

gnapi_dict = {'ip': '8.8.8.8', 'noise': False, 'riot': True,\
 'classification': 'benign', 'name': 'Google Public DNS',\
 'link': 'https://viz.greynoise.io/riot/8.8.8.8',\
 'last_seen': '2021-06-14', 'message': 'Success'}
with open('testGN.txt', 'a+') as f: 
    for key, value in gnapi_dict.items(): 
        f.write(f"{value}, ")


# #OLD hackertarget/shadowserver call tests
# # url = "https://api.shadowserver.org/net/asn?prefix=1128"
# # res = requests.get(url)
# # print(res.text)

# asn_number = 1128
# print(f"We'll look up ASN{asn_number}")
# asnlookup_url = f"https://api.shadowserver.org/net/asn?prefix={asn_number}"
# asnlookup_res = requests.get(asnlookup_url)
# print(f"asnlookup_res is {asnlookup_res}")
# print(f"asnlookup_res.json is {asnlookup_res.json()}")

# asnlist = asnlookup_res.json()
# for i in asnlist:
#     print (i)
# print(asnlist)
# print(type(asnlookup_res.text))

# # asnlist = asntext
# # print(asnlist)

# # asn_net_list = asnlookup_res.text
# # print(f"Networks in {asn} are: {asn_net_list}")
# # print(*asn_net_list, sep='\n')
