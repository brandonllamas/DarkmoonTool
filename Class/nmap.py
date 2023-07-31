import socket , nmap,os,json


class IpScan():
    
 
    
    
    def scanPorts(self,ip):
        nm = nmap.PortScanner()
        scans = nm.scan(hosts=ip,
                             arguments="-n --script='vuln and safe' -sCV -p- -Pn --min-rate 5000 ")
        nm.command_line()
        protocol = nm[ip].all_protocols()
        
        return nm[ip]