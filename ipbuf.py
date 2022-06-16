#!/usr/bin/python 3.7
#coding=utf-8

# Please install first requests
# pip3 install requests

# www.IPBUF.com

import json
import time
import requests

# CookieID UserName After logging in through the browser, you can use F12 debugging to obtain cookie information, which is valid for 3 days
CookieID = ""
UserName = ""

def GetHtml(url):
    response = None
    headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
                'Accept-Encoding': 'gzip, deflate, br',
                'Cookie': 'CookieID=%s; UserName=%s' % (CookieID, UserName),
                'Connection': 'keep-alive'
                }
    try:
        response = requests.get(url, headers = headers, timeout=60).text.lower()
    except Exception as e:
        print(e)
        pass 
    return response

def pdns(iptype, keys, page):
    # iptype: Optional subdm_ipv4 or subdm_ipv6
    # keys: Domain or IP
    # Not logged in to query 1 page
    # After login, free users can query page 1, 2 and 3
    # Charging users can query the first 50 pages
    return GetHtml("https://www.ipbuf.com/site/SearchPDNS/%s/%s/%s" % (iptype, keys, page))

def subdomain(iptype, keys, page):
    # iptype: Optional subdm_ipv4 or subdm_ipv6
    # keys: Domain or IP
    # Not logged in to query 1 page
    # Charging users can query the first 50 pages
    return GetHtml("http://www.ipbuf.com/site/SearchDomain/%s/%s/%s" % (iptype, keys, page))


if __name__=='__main__':
    # The maximum number of requests per hour is 5000, and the IP address will be blocked if it exceeds the limit

    # PDNS Domain IPv4
    print("PDNS API IPv4 www.google.com")
    ipbuf_ipv4 = pdns("pdns_ipv4","www.google.com",1)
    # print(ipbuf_ipv4)
    if ipbuf_ipv4 != None:
        ipbuf_ipv4_json = json.loads(ipbuf_ipv4)
        print("totalcount: %s" % ipbuf_ipv4_json['totalcount'])
        print("maxpage: %s" % ipbuf_ipv4_json['maxpage'])
        print("currentpage: %s" % ipbuf_ipv4_json['currentpage'])
        print("msg: %s" % ipbuf_ipv4_json['msg'])
        for line in ipbuf_ipv4_json['data']:
            domain = line['domain']
            ip = line['ip']
            createtime = time.strftime("%Y-%m-%d", time.localtime(line['createtime'])) 
            updatetime = time.strftime("%Y-%m-%d", time.localtime(line['updatetime']))  
            print("%s\t%s\t%s\t%s" % (domain, ip, createtime, updatetime))

    print('\n')

    # PDNS IP IPv4
    print("PDNS API IPv4 8.8.8.8")
    ipbuf_ipv4_ip = pdns("pdns_ipv4","8.8.8.8",1)
    #print(ipbuf_ipv4_ip)
    if ipbuf_ipv4_ip != None:
        ipbuf_ipv4_json = json.loads(ipbuf_ipv4_ip)
        print("totalcount: %s" % ipbuf_ipv4_json['totalcount'])
        print("maxpage: %s" % ipbuf_ipv4_json['maxpage'])
        print("currentpage: %s" % ipbuf_ipv4_json['currentpage'])
        print("msg: %s" % ipbuf_ipv4_json['msg'])
        for line in ipbuf_ipv4_json['data']:
            domain = line['domain']
            ip = line['ip']
            createtime = time.strftime("%Y-%m-%d", time.localtime(line['createtime'])) 
            updatetime = time.strftime("%Y-%m-%d", time.localtime(line['updatetime']))  
            print("%s\t%s\t%s\t%s" % (domain, ip, createtime, updatetime))

    print('\n')

    # PDNS IPv4 IPs Subnet mask must be 24
    print("PDNS API IPv4s 23.64.202.28+24")
    ipbuf_ipv4s = pdns("pdns_ipv4","23.64.202.28+24",1)
    #print(ipbuf_ipv4s)
    if ipbuf_ipv4s != None:
        ipbuf_ipv4_json = json.loads(ipbuf_ipv4s)
        print("totalcount: %s" % ipbuf_ipv4_json['totalcount'])
        print("maxpage: %s" % ipbuf_ipv4_json['maxpage'])
        print("currentpage: %s" % ipbuf_ipv4_json['currentpage'])
        print("msg: %s" % ipbuf_ipv4_json['msg'])
        for line in ipbuf_ipv4_json['data']:
            domain = line['domain']
            ip = line['ip']
            createtime = time.strftime("%Y-%m-%d", time.localtime(line['createtime'])) 
            updatetime = time.strftime("%Y-%m-%d", time.localtime(line['updatetime']))  
            print("%s\t%s\t%s\t%s" % (domain, ip, createtime, updatetime))

    print('\n')

    # PDNS Domain IPv6
    print("PDNS API IPv6 www.google.com")
    ipbuf_ipv6 = pdns("pdns_ipv6","www.google.com",1)
    #print(ipbuf_ipv6)
    if ipbuf_ipv6 != None:
        ipbuf_ipv6_json = json.loads(ipbuf_ipv6)
        print("totalcount: %s" % ipbuf_ipv6_json['totalcount'])
        print("maxpage: %s" % ipbuf_ipv6_json['maxpage'])
        print("currentpage: %s" % ipbuf_ipv6_json['currentpage'])
        print("msg: %s" % ipbuf_ipv6_json['msg'])
        for line in ipbuf_ipv6_json['data']:
            domain = line['domain']
            ip = line['ip']
            createtime = time.strftime("%Y-%m-%d", time.localtime(line['createtime'])) 
            updatetime = time.strftime("%Y-%m-%d", time.localtime(line['updatetime']))  
            print("%s\t%s\t%s\t%s" % (domain, ip, createtime, updatetime))

    print('\n')

    # PDNS SubDomain IPv4
    print("SubDomain API IPv4 google.com")
    ipbuf_sub_ipv4 = subdomain("subdm_ipv4","google.com",1)
    #print(ipbuf_sub_ipv4)
    if ipbuf_sub_ipv4 != None:
        ipbuf_ipv4_json = json.loads(ipbuf_sub_ipv4)
        print("totalcount: %s" % ipbuf_ipv4_json['totalcount'])
        print("maxpage: %s" % ipbuf_ipv4_json['maxpage'])
        print("currentpage: %s" % ipbuf_ipv4_json['currentpage'])
        print("msg: %s" % ipbuf_ipv4_json['msg'])
        for line in ipbuf_ipv4_json['data']:
            domain = line['dn']
            createtime = time.strftime("%Y-%m-%d", time.localtime(line['cs'])) 
            print("%s\t%s" % (domain, createtime))

    print('\n')

    # PDNS SubDomain IPv6
    print("SubDomain API IPv6 google.com")
    ipbuf_sub_ipv6 = subdomain("subdm_ipv6","google.com",1)
    #print(ipbuf_ipv6)
    if ipbuf_sub_ipv6 != None:
        ipbuf_ipv6_json = json.loads(ipbuf_sub_ipv6)
        print("totalcount: %s" % ipbuf_ipv6_json['totalcount'])
        print("maxpage: %s" % ipbuf_ipv6_json['maxpage'])
        print("currentpage: %s" % ipbuf_ipv6_json['currentpage'])
        print("msg: %s" % ipbuf_ipv6_json['msg'])
        for line in ipbuf_ipv6_json['data']:
            domain = line['dn']
            createtime = time.strftime("%Y-%m-%d", time.localtime(line['cs'])) 
            print("%s\t%s" % (domain, createtime))
