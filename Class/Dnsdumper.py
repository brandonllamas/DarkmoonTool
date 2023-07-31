import requests,re 
from progress.bar import Bar, ChargingBar
from colorama import Fore, Back, Style
from bs4 import BeautifulSoup


class DnsDumperScan():

    def retrieve_results(self, table):
        res = []
        trs = table.findAll('tr')
        for tr in trs:
            tds = tr.findAll('td')
            pattern_ip = r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
            try:
                ip = re.findall(pattern_ip, tds[1].text)[0]
                domain = str(tds[0]).split('<br/>')[0].split('>')[1].split('<')[0]
                header = ' '.join(tds[0].text.replace('\n', '').split(' ')[1:])
                reverse_dns = tds[1].find('span', attrs={}).text

                additional_info = tds[2].text
                country = tds[2].find('span', attrs={}).text
                autonomous_system = additional_info.split(' ')[0]
                provider = ' '.join(additional_info.split(' ')[1:])
                provider = provider.replace(country, '')
                data = {'domain': domain,
                        'ip': ip,
                        'reverse_dns': reverse_dns,
                        'as': autonomous_system,
                        'provider': provider,
                        'country': country,
                        'header': header}
                res.append(data)
            except:
                pass
        return res
    
    def searchDomain(self,domain):
        print("Search Domain with dnsDumper 🕷️")
        # Realizar una solicitud GET a DNSDumpster para obtener el token CSRF
        bar1 = Bar('Procesando:', max=4)
        session = requests.Session()
        response = session.get("https://dnsdumpster.com/")
        soup = BeautifulSoup(response.content, "html.parser")
        csrfmiddlewaretoken = soup.find("input", {"name": "csrfmiddlewaretoken"}).get("value")
        # print(csrfmiddlewaretoken)
        # Enviar la solicitud de búsqueda de subdominios a DNSDumpster
        response = session.post(
            "https://dnsdumpster.com/",
            headers={
                "User-Agent": "Mozilla/5.0",
                "Referer": "https://dnsdumpster.com/",
                "Content-Typ": "application/x-www-form-urlencoded",
            },
            data={
                "csrfmiddlewaretoken": csrfmiddlewaretoken,
                "targetip": domain,
                "user": "free",
            },
            cookies= {
                "csrftoken": f"{csrfmiddlewaretoken}",
                "_ga_FPGN9YXFNE": "GS1.1.1680643203.3.0.1680643449.0.0.0",
                "_ga": "GA1.1.87005704.1678391153",
            }
        )
        bar1.next()
        # Analizar la respuesta HTML para obtener los subdominios
        soup = BeautifulSoup(response.content, "html.parser")
        subdomains_table = soup.findAll("table")
        # print(soup)
        if 'There was an error getting results' in response.content.decode('utf-8'):
            print("There was an error getting results")
            return []
        bar1.next()
        res = {}
        res['domain'] = domain
        res['dns_records'] = {}
        res['dns_records']['dns'] = self.retrieve_results(subdomains_table[0])
        res['dns_records']['mx'] = self.retrieve_results(subdomains_table[1])
        # res['dns_records']['txt'] = self.retrieve_txt_record(subdomains_table[2])
        res['dns_records']['host'] = self.retrieve_results(subdomains_table[3])
        # print(subdomains_table)
        bar1.next()
        dnsFinal = []
        for dns in res['dns_records']['dns']:
            dnsFinal.append({
                    "name":dns["domain"],
                    "ip_server":dns["ip"],
                    "type":"DNS",
                })
            
        for dns in res['dns_records']['mx']:
            dnsFinal.append({
                    "name":dns["domain"],
                    "ip_server":dns["ip"],
                    "type":"MX",
                })
        bar1.next()    
        for dns in res['dns_records']['host']:
            dnsFinal.append({
                    "name":dns["domain"],
                    "ip_server":dns["ip"],
                    "type":"AAA",
                })    
        bar1.finish()
        # print(dnsFinal)
        return dnsFinal