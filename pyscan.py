#!/usr/bin/python

import masscan
import argparse
import sys
import os
import dns.resolver
import pandas
import logging
import coloredlogs
import threading
from queue import Queue

parser = argparse.ArgumentParser(description='Takes a list of hostnames, resolves their ip and\
                                                  performs portscan using masscan')

parser.add_argument('-f', '--file', type=str, metavar='', required=True, help='File containing hostnames')
parser.add_argument('-p', '--ports', type=str, metavar='', required=False, help='Ports to scan.\
                                                                        You can either specify a single port, a list of ports\
                                                                        separated by comma, or a range (default: 1-65535)')

parser.add_argument('-t', '--threads', type=str, metavar='', required=False, help='Number of threads (default 1)')
args = parser.parse_args()

if args.ports == None:
    ports = '1-65535'
else:
    ports = args.ports


logger = logging.getLogger('pyscan')
logger.setLevel(logging.DEBUG)

coloredlogs.install(fmt='[%(asctime)s] [%(levelname)s] %(message)s', level='DEBUG')

q = Queue()
scan_lock = threading.Lock()

def banner():
    print u'\u001b[33;1m-\u001b[0m' * 65
    print u"""\u001b[31;1m
           ____  __  ________________ _____ 
          / __ \/ / / / ___/ ___/ __ `/ __ \\
         / /_/ / /_/ (__  ) /__/ /_/ / / / /
        / .___/\__, /____/\___/\__,_/_/ /_/ 
       /_/    /____/ 
    \u001b[0m
    """

    print u'\u001b[37;1mpyScan - A scanning tool for portscanning a list of hostnames\u001b[0m'
    print u'\u001b[37;1mAuthor: Fellipe Silvestre (montg0mery)\u001b[0m'
    print u'\u001b[33;1m-\u001b[0m' * 65

def getHosts(file):
    with open(file, 'r') as hosts_file:
        hosts = hosts_file.readlines()
        hosts = [x.strip() for x in hosts]
    hosts_file.close()
    return hosts


def getDNSInfo(hostname):
    ids = ['A', 'MX', 'CNAME']
    dns_info = dict()
    
    for i in ids:
        try:
            answer = dns.resolver.query(hostname, i)
            val = []
            for rdata in answer:
                val.append(rdata.to_text())
            dns_info[i] = val
        except Exception:
            pass    
    
    return dns_info


def doPortscan(hostname, ports, redundant):
    info = getDNSInfo(hostname)
    open_ports = []
    if 'A' in info.keys():
        target_ip = info['A'][0]
        if target_ip not in redundant.keys():
            try:
                mas = masscan.PortScanner()
                mas.scan(target_ip, ports=ports, arguments='--max-rate 2000')

                results = mas.scan_result['scan']
                for item in results[target_ip]['tcp'].keys():
                    open_ports.append(item)
            except Exception as e:
                logger.error(e)
        else:
            open_ports = redundant[target_ip]
    return open_ports


def generateReport(results):
    hosts = []
    ips = []
    ports = []

    for item in results:
        hosts.append(item[0])
        ips.append('\n'.join(item[1]))
        ports.append(', '.join(map(str, item[2])))

    df = pandas.DataFrame(data={"HOSTS" : hosts, "IPS" : ips, "PORTS" : ports})
    df.to_csv("./pyscan_log.csv", sep=',', index=False)


results = []
redundant = dict()

def threader():
    while True:
        item = []
        host = q.get()

        logger.info(u'Current host: \u001b[32;1m{}\u001b[0m'.format(host))
        open_ports = doPortscan(host, ports, redundant)
        if len(open_ports) > 0:
            dns_info = getDNSInfo(host)
            ips = dns_info['A']
            item.append(host)
            item.append(ips)
            item.append(open_ports)
            logger.info(u'Ports found open in \u001b[32;1m{}\u001b[0m: \u001b[33;1m{}\u001b[0m'.format(host, ', '.join(map(str, open_ports))))
            redundant[ips[0]] = open_ports
        elif len(open_ports) == 0:
            dns_info = getDNSInfo(host)
            if 'A' not in dns_info.keys():
                logger.warning(u'The DNS query for \u001b[32;1m{}\u001b[0m did not return any A record'.format(host))
                item.append(host)
                item.append('')
                item.append('')
            else:
                logger.warning(u'No ports were found open on \u001b[32;1m{}\u001b[0m'.format(host))
                item.append(host)
                item.append(dns_info['A'])
                item.append('')
        results.append(item)
        q.task_done()


def main():
    banner()

    if os.getuid() != 0:
        logger.critical('This script needs root privileges to run. Aborting now.')
        sys.exit()
    else:    
        hosts = getHosts(args.file)
        logger.info('Total hosts to scan: {}'.format(len(hosts)))

        if args.threads == None:
            threads = 1
        elif int(args.threads) > 20:
            logger.critical('Maximum threads: 20')
        else:
            threads = args.threads

        for x in range(int(threads)):
            t = threading.Thread(target=threader)
            t.daemon = True
            t.start()

        for host in hosts:
            q.put(host)
        
        q.join()
            
        generateReport(results)
        logger.info('Results saved into pyscan_log.csv')
    

if __name__ == '__main__':
    main()
