import os
import json
import time
import random
import urllib3
import argparse
import threading
from colorama import Fore
from ipwhois import IPWhois
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from multiprocessing import Pool, Process, freeze_support

num_threads = 5

ips = []

domain_list = []

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


threadLocal = threading.local()


def get_driver():
    driver = getattr(threadLocal, 'driver', None)
    if driver is None:
        options = Options()
        options.headless = True
        driver = webdriver.Firefox(options=options)
        setattr(threadLocal, 'driver', driver)
    return driver


def whois_history():
    # options = Options()
    # options.headless = True
    # browser = webdriver.Firefox(options=options)
    browser = get_driver()

    for dom in domain_list:
        print(Fore.RESET + "\nGetting whois history for domain: " + dom)
        html_source = ''

        browser.get("https://viewdns.info/iphistory/?domain=" + dom)
        time.sleep(4)
        html_source = browser.page_source
        parsing = BeautifulSoup(html_source, features="html.parser")

        for table in parsing.find_all("table", border="1"):
            trs = table.find_all('tr')

            for tr in trs:
                td = tr.findAll('td')
                info = {'ip': td[0].text, 'owner': td[2].text.rstrip(), 'last': td[3].text}
                print(Fore.GREEN + '\t' + info['ip'] + ', ' + info['owner'] + ' (' + info['last'] + ')')

                file = open("domain_report/" + str(dom) + ".whoishistory.txt", "a")
                file.write(str("\n" + '\t' + info['ip'] + ', ' + info['owner'] + ' (' + info['last'] + ')'))
                file.close()

    browser.close()


def domains(ip_addr):
    print(Fore.RESET + "\nGetting domain info for ip: " + str(ip_addr))
    # Domains
    send1 = http.request("GET", "https://reverseip.domaintools.com/search/?q=" + str(ip_addr))
    parsing2 = BeautifulSoup(send1.data.decode('utf-8'), features="html.parser")
    for data in parsing2.find_all("span", title=str(ip_addr)):
        if data.string is not None:
            print(Fore.GREEN + "Found domain: ", data.string)
            file = open("domain_report/" + str(ip_addr) + ".domains.txt", "a")
            file.write(str(data.string))
            file.close()

            domain_list.append(data.string)

            # Subdomains
            send2 = http.request("GET", "https://dns.bufferover.run/dns?q=" + data.string)
            try:
                parsing3 = send2.data.decode('utf-8')
            except Exception as exc:
                print(Fore.RESET + "Error:\n" + str(exc) + "Trying latin-1...")
                parsing3 = send2.data.decode('latin-1')
            json_response = json.loads(parsing3)
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
    print(Fore.RESET + "\nGetting whois info for ip: " + str(ip_addr))

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
        print(Fore.YELLOW + "\nAll found data was written in 'dorker_report' folder")
        print(Fore.RESET + " ")

    elif args.mode == "domain":
        for addr in ips:
            domains(addr)

        whois_history()

        print(Fore.YELLOW + "\nAll found data was written in 'domain_report' and 'whois_report' folder")
        print(Fore.RESET + " ")

    elif args.mode == "whois":
        freeze_support()
        pool_whois = Pool(num_threads)
        pool_whois.map(whois, ips)
        pool_whois.close()
        pool_whois.join()

        print(Fore.YELLOW + "\nAll found data was written in 'whois_report' folder")
        print(Fore.RESET + " ")

    elif args.mode == "all":
        for addr in ips:
            dorks(addr)
            domains(addr)

        whois_history()

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
