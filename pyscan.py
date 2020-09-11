#!/usr/bin/python

import masscan
import argparse
import sys
import os
import dns.resolver
import pandas
import logging
import coloredlogs

logger = logging.getLogger('pyscan')
logger.setLevel(logging.DEBUG)

coloredlogs.install(fmt='[%(asctime)s] [%(levelname)s] %(message)s', level='DEBUG')

def getHosts(file):
    with open(file, 'r') as hosts_file:
        hosts = hosts_file.readlines()
        hosts = [x.strip() for x in hosts]
    hosts_file.close()
    return hosts


def getDNSInfo(hostname):
    ids = ['A', 'CNAME']
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
                mas.scan(target_ip, ports=ports, arguments='--max-rate 5000')

                results = mas.scan_result['scan']
                for item in results[target_ip]['tcp'].keys():
                    open_ports.append(item)
            except Exception:
                logger.error('Network is unreachable')
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

    df = pandas.DataFrame(data={"hosts" : hosts, "ips" : ips, "ports" : ports})
    df.to_csv("./pyscan_log.csv", sep=',', index=False)


def main():
    parser = argparse.ArgumentParser(description='Takes a list of hostnames, resolves their ip and\
                                                  performs portscan using masscan')

    parser.add_argument('-f', '--file', type=str, required=True, help='File containing hostnames')
    parser.add_argument('-p', '--port', type=str, required=False, help='Ports to scan.\
                                                                        You can either specify a single port, a list of ports\
                                                                        separated by comma, or a range (default: 1-65535)')

    args = parser.parse_args()

    if os.getuid() != 0:
        logger.critical('This script needs root privileges to run. Aborting now.')
        sys.exit()
    else:    
        if args.port == None:
            ports = '1-65535'
        else:
            ports = args.port
        
        hosts = getHosts(args.file)

        results = []
        redundant = dict()

        logger.info('Total hosts to scan: {}'.format(len(hosts)))
        for host in hosts:
            item = []
            logger.info('Current target: {}'.format(host))
            open_ports = doPortscan(host, ports, redundant)
            if len(open_ports) > 0:
                dns_info = getDNSInfo(host)
                ips = dns_info['A']
                item.append(host)
                item.append(ips)
                item.append(open_ports)
                logger.info('Ports found open in {}: {}'.format(host, ', '.join(map(str, open_ports))))
                redundant[ips[0]] = open_ports
            elif len(open_ports) == 0:
                dns_info = getDNSInfo(host)
                if 'A' not in dns_info.keys():
                    logger.warning('The DNS query for {} did not return any A record'.format(host))
                    item.append(host)
                    item.append('')
                    item.append('')
                else:
                    logger.warning('No ports were found open on {}'.format(host))
                    item.append(host)
                    item.append(dns_info['A'])
                    item.append('')
            results.append(item)
        generateReport(results)
        logger.info('Results saved into pyscan_log.csv')
    

if __name__ == '__main__':
    main()
