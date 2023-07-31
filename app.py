import cowsay,sys,argparse,json,os,webtech
from progress.bar import Bar, ChargingBar
from colorama import Fore, Back, Style
from Class.Dnsdumper import DnsDumperScan
from Class.Utils import Utils
from Class.nmap import IpScan
from concurrent.futures import ThreadPoolExecutor, as_completed

print('================================================================')
print(cowsay.get_output_string('tux', 'Bienvenido a mi mundo!! '))
print('Created by: DarkmoonPwned')
print('Github: https://github.com/brandonllamas')
print('================================================================')

parser = argparse.ArgumentParser()
parser.add_argument("-ip", "--ip", 
                    help="Escanear una ip")
parser.add_argument("-D", "--domain", 
                    help="Escanear una dominio")
parser.add_argument("-Nmap", "--Nonmap", 
                    help="Que no escane con nmap",
                    action='store_true')
parser.add_argument("-Sd", 
                    help="Escanear los subdominios de un dominio",
                    action='store_true')
args = parser.parse_args()

def crearCarpeta(domain):
    try:
        print('Creando directorio')
        os.mkdir('out/{}'.format(domain))
        os.mkdir('out/{}/data'.format(domain))
        os.mkdir('out/{}/xls'.format(domain))
    except:
        print('Archivo ya se encuentra creado')


def process_ip(ip):
    print('procesando ip => {}'.format(ip))
    return IpScan().scanPorts(ip)

def process_domain(domain):
  
    
    print('procesando dominio => http://{}'.format(domain))
    
    wt = webtech.WebTech(options={'json': True})
    try:
        report = wt.start_from_url('http://{}'.format(domain))
        # print(report)
        return report
    except Exception as e:
        print("Connection error")
        return []
    
threads = 5
nmap = True
# ================================================================
#     VALIDAMOS SCAN CON DOMINIO
# ================================================================

def processDomain(subdomains):
    bar2 = Bar('Procesando dominios:', max=(len(subdomains)+1))
    finalJson = []
    for subdomain in subdomains:
        bar2.next()
        
        if subdomain['type'] == 'AAA': 
            subdomain['technology'] = process_domain(subdomain['name'])
            subdomain['shodan_url'] = "https://www.shodan.io/host/{}".format(subdomain['ip_server'])
            if nmap :
                subdomain['ports_nmap'] = process_ip(subdomain['ip_server'])
            
        finalJson.append(subdomain)  
    bar2.finish()
    jsonSubdomain = json.dumps(finalJson)
    f  = open('out/{}/data/domain.json'.format(domain),'w+')
    f.write(jsonSubdomain)

if args.Nonmap:
    nmap = False
    
if args.domain:
    domain = args.domain
    print('nmap ?  => {}'.format(nmap))
    print('Escaneando El Dominio =>',domain)
    crearCarpeta(domain)
    dnsDumper = DnsDumperScan()
    subdomains =dnsDumper.searchDomain(domain)
    print("Subdominios encontrados")
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future = executor.submit(processDomain, subdomains)
        future.result()
    print("Escaneo de dominio completado.")
# ================================================================
#     VALIDAMOS SCAN CON IP
# ================================================================


if args.ip:
    print('Escaneando ip ..')
    print(args.ip)