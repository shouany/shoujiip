import os
import requests
from bs4 import BeautifulSoup
import re

UOUIN = 'https://api.uouin.com/cloudflare.html'
IPXYZ = 'https://ip.164746.xyz'
CFXYZ = 'https://cf.090227.xyz'
HOSTMONIT = 'https://stock.hostmonit.com/CloudFlareYes'
WETEST = 'https://www.wetest.vip/page/cloudflare/address_v4.html'
TDPOS = {UOUIN: (1, 0, None), IPXYZ: (0, None, None), CFXYZ: (1, 0, None), HOSTMONIT: (1, 0, 5), WETEST: (1, 0, 5)}
urls = [UOUIN, IPXYZ, CFXYZ, HOSTMONIT, WETEST]
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0"}
ipsfile = 'collection.txt'
ipsColoFile = 'collection_colo.txt'
AREA = {'移动': 'CMCC', '联通': 'CU', '电信': 'CT'}
ips = {}
if os.path.isfile(ipsfile):
    os.remove(ipsfile)
if os.path.isfile(ipsColoFile):
    os.remove(ipsColoFile)


def extract_ips(text):
    # IPv4: 严格 0-255
    OCTET = r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
    IPV4 = rf'(?<![\d.])(?:{OCTET}\.){{3}}{OCTET}(?![\d.])'

    # IPv6 基元
    H16 = r'[A-Fa-f0-9]{1,4}'
    ZONE_ID = r'(?:%[0-9A-Za-z.\-]+)?'
    IPV4_EMBEDDED = rf'(?:{OCTET}\.){{3}}{OCTET}'

    # IPv6 模式（包含压缩、IPv4嵌入、zone id）
    IPV6 = rf'''
        (?<![A-Fa-f0-9:])(?:
            (?:{H16}:){{7}}{H16} |
            (?:{H16}:){{1,7}}: |
            (?:{H16}:){{1,6}}:{H16} |
            (?:{H16}:){{1,5}}:(?:{H16}){{1}} |
            (?:{H16}:){{1,5}}(?::{H16}){{1,2}} |
            (?:{H16}:){{1,4}}(?::{H16}){{1,3}} |
            (?:{H16}:){{1,3}}(?::{H16}){{1,4}} |
            (?:{H16}:){{1,2}}(?::{H16}){{1,5}} |
            (?:{H16}:){{6}}{IPV4_EMBEDDED} |
            (?:{H16}:){{1,5}}:(?:{H16}:){{1,1}}{IPV4_EMBEDDED} |
            (?:{H16}:){{1,4}}:(?:{H16}:){{1,2}}{IPV4_EMBEDDED} |
            (?:{H16}:){{1,3}}:(?:{H16}:){{1,3}}{IPV4_EMBEDDED} |
            (?:{H16}:){{1,2}}:(?:{H16}:){{1,4}}{IPV4_EMBEDDED} |
            {H16}:(?:{H16}:){{1,5}}{IPV4_EMBEDDED} |
            :(?::(?:{H16})){{1,6}}{IPV4_EMBEDDED} |
            {H16}:(?:(?::{H16}){{1,6}}) |
            :(?:(?::{H16}){{1,7}}|:) |
            (?:{H16}:){{6}}{IPV4_EMBEDDED} |
            (?:{H16}:){{0,5}}:(?:{IPV4_EMBEDDED}) |
            ::(?:{H16}:){{0,4}}{IPV4_EMBEDDED}
        ){ZONE_ID}(?![A-Fa-f0-9:])
    '''
    ipv4_matches = re.findall(IPV4, text)
    ipv6_matches = [m[0] if isinstance(m, tuple) else m for m in re.findall(IPV6, text,  re.IGNORECASE | re.VERBOSE)]
    # ipv6_pattern = re.compile(IPV6, re.IGNORECASE | re.VERBOSE)
    # ipv6_matches = [m.group(0) for m in ipv6_pattern.finditer(text)]

    return {
        'ipv4': ipv4_matches,
        'ipv6': ipv6_matches
    }


for i, url in enumerate(urls):
    try:
        res = requests.get(url, headers=HEADERS)
        res.raise_for_status()
        soup = BeautifulSoup(res.text, 'html.parser')
        table = soup.select_one('table')
        trs = table.select('tr')
        for i in range(1, len(trs)):
            tr = trs[i]
            tds = tr.select('td')
            ip, line, colo = '', '', ''
            pos = TDPOS[url]
            if pos[0] is not None:
                ip_dict = extract_ips(tds[pos[0]].get_text().strip())
                ipvn = ip_dict['ipv6'] or ip_dict['ipv4'] or ['']
                ip = ipvn[0]
            if pos[1] is not None:
                line = tds[pos[1]].get_text().strip()
            if pos[2] is not None:
                colo = tds[pos[2]].get_text().strip()
            if ip:
                templist = ips.get(ip,['',''])
                temp = {ip:[line or templist[0], colo or templist[1]]}
                ips.update(temp)
    except Exception as e:
        print(f'Error occur when request {url}')
        print(repr(e))
if ips.keys():
    try:
        with open(ipsfile, 'w', encoding='utf-8') as ipfile:
            for ip in ips:
                try:
                    ipfile.write(f'{ip}\n')
                except Exception as e:
                    print('Error occur when write ip')
                    print(repr(e))
        print(f'已保存{ipsfile}')
    except Exception as e:
        print(repr(e))
    try:
        with open(ipsColoFile, 'w', encoding='utf-8') as ipcolofile:
            for ip in ips:
                try:
                    colo = ips[ip][1] or ips[ip][0]
                    colo = AREA.get(colo, colo)
                    newline = f'{ip}#{colo}\n' if colo else f'{ip}#CF优选\n'
                    ipcolofile.write(newline)
                except Exception as e:
                    print('Error occur when write ip#colo')
                    print(repr(e))
        print(f'已保存{ipsColoFile}')
    except Exception as e:
        print(repr(e))
