import os
import json
import random
import urllib3
import argparse
from ipwhois import IPWhois
from bs4 import BeautifulSoup
from multiprocessing import Pool, Process, freeze_support

num_threads = 5

ips = []

ua = ['Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; zh-cn) Opera 8.65',
      'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; en) Opera 8.50',
      'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; en) Opera 9.50',
      'Opera/9.10 (Windows NT 6.0; U; en)',
      'Opera/9.10 (Windows NT 6.0; U; it-IT)',
      'Opera/9.10 (X11; Linux i386; U; en)',
      'Opera/9.10 (X11; Linux i686; U; en)',
      'Mozilla/4.0 (compatible; MSIE 4.0; Windows 95)',
      'Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0; MSIECrawler)']

header = {
    'User-agent': random.choice(ua),
    'Accept-Encoding': 'gzip, deflate',
    'Accept': '*/*',
    'Connection': 'keep-alive'
}
http = urllib3.PoolManager(2, headers=header)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def whois(addr):
    result = {}
    info = IPWhois(addr).lookup_rdap(depth=1)
    result['info'] = info
    entity = info['entities'][0]
    result['entity'] = entity
    name = info['objects'][entity]['contact']['name']
    result['name'] = name
    json_beauty = json.dumps(result, indent=4)

    print("\nGetting whois info for ip: " + str(addr))

    file = open("whois_report/" + str(addr) + ".ip_info.txt", "w")
    file.write(str(json_beauty))
    file.close()


def dorks(addr):
    print("\nGetting info from www1.search-results.com for ip: " + str(addr))
    for pages in range(6):
        send = http.request("GET", "http://www1.search-results.com/web?q=intext:" + str(addr) + "&page=" + str(pages))
        try:
            parsing = BeautifulSoup(send.data.decode('utf-8'), features="html.parser")
        except Exception as ex:
            print("Error:\n" + str(ex) + "Trying latin-1...")
            parsing = BeautifulSoup(send.data.decode('latin-1'), features="html.parser")

        for data in parsing.find_all("cite"):
            f = open("dorker_report/" + str(addr) + ".dorker_result.txt", "a", encoding="utf=8")
            f.write(data.string + "\n")
            f.close()


if __name__ == '__main__':
    if os.name in ('nt', 'dos'):
        os.system("cls")
    elif os.name in ('linux', 'osx', 'posix'):
        os.system("clear")

    ip_list = ''

    parser = argparse.ArgumentParser()
    parser.add_argument('-m', dest="mode", default="all", type=str)
    parser.add_argument('-f', dest="file", default="ip_list.txt", type=str)
    args = parser.parse_args()

    try:
        file_with_ip = open(str(args.file), "r")
        ip_list = [line for line in file_with_ip.readlines()]
        file_with_ip.close()
    except:
        print("Seems you don`t enter file with ip, try again.")

    for ip in ip_list:
        try:
            ips.append(ip.split("\n")[0])
        except:
            ips.append(ip)

    if args.mode == "dork":
        for addr in ips:
            dorks(addr)

    elif args.mode == "whois":
        freeze_support()
        pool_whois = Pool(num_threads)
        pool_whois.map(whois, ips)
        pool_whois.close()
        pool_whois.join()

    elif args.mode == "all":
        for addr in ips:
            dorks(addr)

        freeze_support()
        pool_whois = Pool(num_threads)
        pool_whois.map(whois, ips)
        pool_whois.close()
        pool_whois.join()

    else:
        print("""
        Choose one of three modes:
        
        python3 ipinfo.py -f file_with_ip.txt -m dork
        python3 ipinfo.py -f file_with_ip.txt -m whois
        python3 ipinfo.py -f file_with_ip.txt -m all
        
        Default values:
        -f - ip_list.txt
        -m - all
        """)
        exit(0)
