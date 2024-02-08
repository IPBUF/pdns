#!/usr/bin/python 3.7
#coding=utf-8

# Please install first requests
# pip3 install requests

# www.ipbuf.com

import json
import time
import requests

# Obtain Token After Successful Login
token = "****************************************************************"

def GetHtml(url):
    response = None
    headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
                'Accept-Encoding': 'gzip, deflate',
                'IPBUF-AUTH': token,
                'Connection': 'keep-alive'
                }
    try:
        response = requests.get(url, headers = headers, timeout=180, verify=False).text.lower()
    except Exception as e:
        print(e)
        pass 
    return response

def search(iptype, key_type, key, net_mask, page):

    # GET /api/search/{ip_type}/{key_type}/{key}/{net_mask}/{page}

    # GET /api/search/ipv4/domain/www.google.com/-1/1
    # ip_type = ipv4
    # key_type = domain
    # key = www.google.com
    # net_mask = -1
    # page = 1

    # GET /api/search/ipv4/ip/1.1.1.1/24/1
    # ip_type = ipv4
    # key_type = ip
    # key = 1.1.1.1
    # net_mask = 24/32
    # page = 1

    # ipv4 net_mask 32/24
    # ipv6 net_mask 128/112
    # domain net_mask -1
    return GetHtml("https://www.ipbuf.com/api/search/%s/%s/%s/%s/%s" % (iptype, key_type, key, net_mask, page))

def searchx(iptype, key_type, key, net_mask, page):

    # GET /api/searchx/{ip_type}/{key_type}/{key}/{net_mask}/{page}

    # GET /api/searchx/ipv4/ip/162.243.134.7/24/1
    # ip_type = ipv4
    # key_type = ip
    # key = 162.243.134.7
    # net_mask = 24/32
    # page = 1

    # ipv4 net_mask 32/24
    # ipv6 net_mask 128/112
    # domain net_mask -1
    return GetHtml("https://www.ipbuf.com/api/searchx/%s/%s/%s/%s/%s" % (iptype, key_type, key, net_mask, page))

if __name__=='__main__':
    # Limit queries to 3 times every 10 seconds. The IP address will be blocked if it exceeds the limit

    # PDNS Domain IPv4
    print("PDNS API IPv4 www.google.com")
    ipbuf_ipv4 = search("ipv4", "domain", "www.google.com", -1, 1)
    if ipbuf_ipv4 != None:
        ipbuf_ipv4_json = json.loads(ipbuf_ipv4)
        print("totalcount: %s" % ipbuf_ipv4_json['totalcount'])
        print("maxpage: %s" % ipbuf_ipv4_json['maxpage'])
        print("currentpage: %s" % ipbuf_ipv4_json['currentpage'])
        print("msg: %s" % ipbuf_ipv4_json['msg'])
        for line in ipbuf_ipv4_json['data']:
            domain = line['d']
            ip = line['i']
            createtime = time.strftime("%Y-%m-%d", time.localtime(line['c'])) 
            updatetime = time.strftime("%Y-%m-%d", time.localtime(line['u']))  
            print("%s\t%s\t%s\t%s" % (domain, ip, createtime, updatetime))
    time.sleep(5)
    print('\n')


    # PDNS Domain IPv6
    print("PDNS API IPv6 www.google.com")
    ipbuf_ipv6 = search("ipv6", "domain", "www.google.com", -1, 1)
    if ipbuf_ipv6 != None:
        ipbuf_ipv6_json = json.loads(ipbuf_ipv6)
        print("totalcount: %s" % ipbuf_ipv6_json['totalcount'])
        print("maxpage: %s" % ipbuf_ipv6_json['maxpage'])
        print("currentpage: %s" % ipbuf_ipv6_json['currentpage'])
        print("msg: %s" % ipbuf_ipv6_json['msg'])
        for line in ipbuf_ipv6_json['data']:
            domain = line['d']
            ip = line['i']
            createtime = time.strftime("%Y-%m-%d", time.localtime(line['c'])) 
            updatetime = time.strftime("%Y-%m-%d", time.localtime(line['u']))  
            print("%s\t%s\t%s\t%s" % (domain, ip, createtime, updatetime))
    time.sleep(5)
    print('\n')


    # PDNS IP IPv4
    print("PDNS API IPv4 8.8.8.8")
    ipbuf_ipv4_ip = search("ipv4", "ip", "1.1.1.1", 32, 1)
    if ipbuf_ipv4_ip != None:
        ipbuf_ipv4_json = json.loads(ipbuf_ipv4_ip)
        print("totalcount: %s" % ipbuf_ipv4_json['totalcount'])
        print("maxpage: %s" % ipbuf_ipv4_json['maxpage'])
        print("currentpage: %s" % ipbuf_ipv4_json['currentpage'])
        print("msg: %s" % ipbuf_ipv4_json['msg'])
        for line in ipbuf_ipv4_json['data']:
            domain = line['d']
            ip = line['i']
            createtime = time.strftime("%Y-%m-%d", time.localtime(line['c'])) 
            updatetime = time.strftime("%Y-%m-%d", time.localtime(line['u']))  
            print("%s\t%s\t%s\t%s" % (domain, ip, createtime, updatetime))
    time.sleep(5)
    print('\n')


    # PDNS IP IPv6
    print("PDNS API IPv6 2001::1f0d:4a0c")
    ipbuf_ipv6_ip = search("ipv6", "ip", "2001::1f0d:4a0c", 128, 1)
    if ipbuf_ipv6_ip != None:
        ipbuf_ipv6_json = json.loads(ipbuf_ipv6_ip)
        print("totalcount: %s" % ipbuf_ipv6_json['totalcount'])
        print("maxpage: %s" % ipbuf_ipv6_json['maxpage'])
        print("currentpage: %s" % ipbuf_ipv6_json['currentpage'])
        print("msg: %s" % ipbuf_ipv6_json['msg'])
        for line in ipbuf_ipv6_json['data']:
            domain = line['d']
            ip = line['i']
            createtime = time.strftime("%Y-%m-%d", time.localtime(line['c'])) 
            updatetime = time.strftime("%Y-%m-%d", time.localtime(line['u']))  
            print("%s\t%s\t%s\t%s" % (domain, ip, createtime, updatetime))
    time.sleep(5)
    print('\n')


    # PDNS IPv4 IPs Subnet mask must be 24
    print("PDNS API IPv4s 208.43.237.140/24")
    ipbuf_ipv4s = search("ipv4", "ip", "208.43.237.140", 24, 1)
    if ipbuf_ipv4s != None:
        ipbuf_ipv4_json = json.loads(ipbuf_ipv4s)
        print("totalcount: %s" % ipbuf_ipv4_json['totalcount'])
        print("maxpage: %s" % ipbuf_ipv4_json['maxpage'])
        print("currentpage: %s" % ipbuf_ipv4_json['currentpage'])
        print("msg: %s" % ipbuf_ipv4_json['msg'])
        for line in ipbuf_ipv4_json['data']:
            domain = line['d']
            ip = line['i']
            createtime = time.strftime("%Y-%m-%d", time.localtime(line['c'])) 
            updatetime = time.strftime("%Y-%m-%d", time.localtime(line['u']))  
            print("%s\t%s\t%s\t%s" % (domain, ip, createtime, updatetime))
    time.sleep(5)
    print('\n')


    # PDNS IPv6 IPs Subnet mask must be 112
    print("PDNS API IPv6s 2001::1f0d:4a0c/112")
    ipbuf_ipv6s = search("ipv6", "ip", "2001::1f0d:4a0c", 112, 1)
    if ipbuf_ipv6s != None:
        ipbuf_ipv6_json = json.loads(ipbuf_ipv6s)
        print("totalcount: %s" % ipbuf_ipv6_json['totalcount'])
        print("maxpage: %s" % ipbuf_ipv6_json['maxpage'])
        print("currentpage: %s" % ipbuf_ipv6_json['currentpage'])
        print("msg: %s" % ipbuf_ipv6_json['msg'])
        for line in ipbuf_ipv6_json['data']:
            domain = line['d']
            ip = line['i']
            createtime = time.strftime("%Y-%m-%d", time.localtime(line['c'])) 
            updatetime = time.strftime("%Y-%m-%d", time.localtime(line['u']))  
            print("%s\t%s\t%s\t%s" % (domain, ip, createtime, updatetime))
    time.sleep(5)
    print('\n')


    # PDNS SubDomain IPv4
    print("SubDomain API IPv4 google.com")
    ipbuf_sub_ipv4 = search("ipv4", "sub", "google.com", -1, 1)
    if ipbuf_sub_ipv4 != None:
        ipbuf_ipv4_json = json.loads(ipbuf_sub_ipv4)
        print("totalcount: %s" % ipbuf_ipv4_json['totalcount'])
        print("maxpage: %s" % ipbuf_ipv4_json['maxpage'])
        print("currentpage: %s" % ipbuf_ipv4_json['currentpage'])
        print("msg: %s" % ipbuf_ipv4_json['msg'])
        for line in ipbuf_ipv4_json['data']:
            domain = line['d']
            createtime = time.strftime("%Y-%m-%d", time.localtime(line['c'])) 
            print("%s\t%s" % (domain, createtime))
    time.sleep(5)
    print('\n')


    # PDNS SubDomain IPv6
    print("SubDomain API IPv6 google.com")
    ipbuf_sub_ipv6 = search("ipv6", "sub", "google.com", -1, 1)
    if ipbuf_sub_ipv6 != None:
        ipbuf_ipv6_json = json.loads(ipbuf_sub_ipv6)
        print("totalcount: %s" % ipbuf_ipv6_json['totalcount'])
        print("maxpage: %s" % ipbuf_ipv6_json['maxpage'])
        print("currentpage: %s" % ipbuf_ipv6_json['currentpage'])
        print("msg: %s" % ipbuf_ipv6_json['msg'])
        for line in ipbuf_ipv6_json['data']:
            domain = line['d']
            createtime = time.strftime("%Y-%m-%d", time.localtime(line['c'])) 
            print("%s\t%s" % (domain, createtime))


    # Threat Intelligence X IPv4
    print("Threat Intelligence API IPv4 162.243.134.7")
    ipbuf_sub_ipv4 = searchx("ipv4", "xip", "162.243.134.7", 32, 1)
    if ipbuf_sub_ipv4 != None:
        ipbuf_ipv4_json = json.loads(ipbuf_sub_ipv4)
        print("totalcount: %s" % ipbuf_ipv4_json['totalcount'])
        print("maxpage: %s" % ipbuf_ipv4_json['maxpage'])
        print("currentpage: %s" % ipbuf_ipv4_json['currentpage'])
        print("msg: %s" % ipbuf_ipv4_json['msg'])
        for line in ipbuf_ipv4_json['data']:
            ip = line['i']
            pt = line['pt']
            pr = line['pr']
            createtime = time.strftime("%Y-%m-%d", time.localtime(line['c']))
            updatetime = time.strftime("%Y-%m-%d", time.localtime(line['u']))
            print("%s\t%s\t%s\t%s\t%s" % (ip, pt, pr, createtime, updatetime))


    # Threat Intelligence X IPv4s Subnet mask must be 24
    print("Threat Intelligence API IPv4 162.243.134.7")
    ipbuf_sub_ipv4 = searchx("ipv4", "xip", "162.243.134.7", 24, 1)
    if ipbuf_sub_ipv4 != None:
        ipbuf_ipv4_json = json.loads(ipbuf_sub_ipv4)
        print("totalcount: %s" % ipbuf_ipv4_json['totalcount'])
        print("maxpage: %s" % ipbuf_ipv4_json['maxpage'])
        print("currentpage: %s" % ipbuf_ipv4_json['currentpage'])
        print("msg: %s" % ipbuf_ipv4_json['msg'])
        for line in ipbuf_ipv4_json['data']:
            ip = line['i']
            pt = line['pt']
            pr = line['pr']
            createtime = time.strftime("%Y-%m-%d", time.localtime(line['c']))
            updatetime = time.strftime("%Y-%m-%d", time.localtime(line['u']))
            print("%s\t%s\t%s\t%s\t%s" % (ip, pt, pr, createtime, updatetime))

    
