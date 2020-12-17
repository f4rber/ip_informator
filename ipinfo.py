import os
import json
import random
import urllib3
import argparse
from colorama import Fore
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


def domains(ip_addr):
    print(Fore.RESET + "\nGetting domain info for ip: " + str(ip_addr))
    send1 = http.request("GET", "https://reverseip.domaintools.com/search/?q=" + str(ip_addr))
    parsing = BeautifulSoup(send1.data.decode('utf-8'), features="html.parser")
    for data in parsing.find_all("span", title=str(ip_addr)):
        if data.string is not None:
            print(Fore.GREEN + "Found domain: ", data.string)
            file = open("domain_report/" + str(ip_addr) + ".domains.txt", "a")
            file.write(str(data.string))
            file.close()

            send2 = http.request("GET", "https://dns.bufferover.run/dns?q=" + data.string)
            try:
                parsing = send2.data.decode('utf-8')
            except Exception as exc:
                print(Fore.RESET + "Error:\n" + str(exc) + "Trying latin-1...")
                parsing = send2.data.decode('latin-1')

            json_response = json.loads(parsing)
            subdomain_list = json_response['FDNS_A']
            if subdomain_list is not None:
                for subdomain in subdomain_list:
                    try:
                        print(Fore.GREEN + "Found subdomain: ", str(subdomain))

                        file = open("domain_report/" + str(ip_addr) + ".domains.txt", "a")
                        file.write("\n" + str(subdomain))
                        file.close()
                    except:
                        pass


def whois(ip_addr):
    result = {}
    info = IPWhois(ip_addr).lookup_rdap(depth=1)
    result['info'] = info
    entity = info['entities'][0]
    result['entity'] = entity
    name = info['objects'][entity]['contact']['name']
    result['name'] = name
    json_beauty = json.dumps(result, indent=4)

    file = open("whois_report/" + str(ip_addr) + ".whois.json", "w")
    file.write(str(json_beauty))
    file.close()

    print(Fore.RESET + "\nGetting whois info for ip: " + str(ip_addr))


def dorks(ip_addr):
    print(Fore.RESET + "\nGetting info from http://www1.search-results.com for ip: " + str(ip_addr))
    for pages in range(6):
        send = http.request("GET", "http://www1.search-results.com/web?q=intext:" + str(ip_addr) +
                            "&page=" + str(pages))
        try:
            parsing = BeautifulSoup(send.data.decode('utf-8'), features="html.parser")
        except Exception as exc:
            print(Fore.RED + "Error:\n" + str(exc) + "Trying latin-1...")
            parsing = BeautifulSoup(send.data.decode('latin-1'), features="html.parser")

        for data in parsing.find_all("cite"):
            f = open("dorker_report/" + str(ip_addr) + ".dorker.txt", "a", encoding="utf=8")
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
    except Exception as ex:
        print(Fore.RED + "Seems you don`t enter file with ip, try again.\n" + str(ex))

    for ip in ip_list:
        try:
            ips.append(ip.split("\n")[0])
        except:
            ips.append(ip)

    if args.mode == "dork":
        for addr in ips:
            dorks(addr)
        print(Fore.YELLOW + "\nAll found data was write in 'dorker_report' folder")
        print(Fore.RESET + " ")

    elif args.mode == "domain":
        for addr in ips:
            domains(addr)
        print(Fore.YELLOW + "\nAll found data was write in 'domain_report' folder")
        print(Fore.RESET + " ")

    elif args.mode == "whois":
        freeze_support()
        pool_whois = Pool(num_threads)
        pool_whois.map(whois, ips)
        pool_whois.close()
        pool_whois.join()

        print(Fore.YELLOW + "\nAll found data was write in 'whois_report' folder")
        print(Fore.RESET + " ")

    elif args.mode == "all":
        for addr in ips:
            dorks(addr)
            domains(addr)

        freeze_support()
        pool_whois = Pool(num_threads)
        pool_whois.map(whois, ips)
        pool_whois.close()
        pool_whois.join()

        print(Fore.YELLOW + "\nAll found data was written in 'whois_report', "
                            "'dorker_report' and 'domain_report' folders")
        print(Fore.RESET + " ")

    elif args.mode == "help":
        print(Fore.RESET + "Choose one of four modes:\n")
        print(Fore.YELLOW + "python3 ipinfo.py -f file_with_ip.txt -m dork\n"
                            "python3 ipinfo.py -f file_with_ip.txt -m whois\n"
                            "python3 ipinfo.py -f file_with_ip.txt -m domain\n"
                            "python3 ipinfo.py -f file_with_ip.txt -m all\n\n"
                            "Default values:\n-f - ip_list.txt\n-m - all")

        print(Fore.RESET + " ")
        exit(0)

    else:
        exit(0)
