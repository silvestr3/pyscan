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
import requests

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

    df = pandas.DataFrame(data={"HOSTS" : hosts,
                                "IPS" : ips,
                                "PORTS" : ports,
                                })
    df.to_csv("./pyscan_log.csv", sep=',', index=False)


def takeoverCheck(host):
    cname = getDNSInfo(host)['CNAME']

    domains = {
        'Agile CRM' : ['agilecrm.com'],
        'Airee.ru' : ['airee.ru'],
        'Anima' : ['animaapp.com'],
        'AWS/S3' : ['s3.amazonaws.com'],
        'Bitbucket' : ['bitbucket.org'],
        'Campaign Monitor' : ['createsend.com'],
        'Cargo Collective' : ['cargocollective.com'],
        'Digital Ocean' : ['digitalocean.com'],
        'Fastly' : ['fastly.net'],
        'Feedpress' : ['feedpress.me'],
        'Fly.io' : ['fly.io'],
        'Gemfury' : ['gemfury.com', 'furyns.com'],
        'Ghost' : ['ghost.io'],
        'Github' : ['github.io'],
        'HatenaBlog' : ['hatenablog.com'],
        'Help Juice' : ['helpjuice.com'],
        'Help Scout' : ['helpscoutdocs.com'],
        'Heroku' : ['herokudns.com', 'herokuapp.com', 'herokussl.com'],
        'Intercom' : ['intercom.help'],
        'JetBrains' : ['myjetbrains.com'],
        'Kinsta' : ['kinstasite.com', 'kinsta.cloud'],
        'LaunchRock' : ['launchrock.com'],
        'Microsoft Azure' : ['cloudapp.net', 'cloudapp.azure.com', 'azurewebsites.net', 'blob.core.windows.net',
                            'cloudapp.azure.com', 'azure-api.net', 'azurehdinsight.net', 'azureedge.net',
                            'azurecontainer.io', 'database.windows.net', 'azuredatalakestore.net', 'search.windows.net',
                            'azurecr.io', 'redis.cache.windows.net', 'azurehdinsight.net', 'servicebus.windows.net',
                            'visualstudio.com'],
        'Netlify' : ['netlify.com'],
        'Ngrok' : ['ngrok.com', 'ngrok.io'],
        'Pantheon' : ['pantheon.io'],
        'Pingdom' : ['pingdom.com'],
        'Readme.io': ['readme.io'],
        'Shopify' : ['myshopify.com', 'shops.myshopify.com'],
        'SmartJobBoard' : ['smartjobboard.com', 'mysmartjobboard.com'],
        'Statuspage' : ['stspg-customer.com'],
        'Strikingly' : ['strikinglydns.com'],
        'Surge.sh' : ['surge.sh'],
        'Tumblr' : ['tumblr.com'],
        'Tilda' : ['tilda'],
        'Uberflip' : ['uberflip.com'],
        'Uptimerobot' : ['uptimerobot.com'],
        'UserVoice' : ['uservoice.com'],
        'Wordpress' : ['wordpress.com'],
        'Worksites' : ['worksites.net']
    }

    fingerprints = {
        'Agile CRM' : 'Sorry, this page is no longer available.',
        'Airee.ru' : ' ',
        'Anima' : 'If this is your website and you\'ve just created it, try refreshing in a minute',
        'AWS/S3' : 'The specified bucket does not exist',
        'Bitbucket' : 'Repository not found',
        'Campaign Monitor' : 'Trying to access your account?',
        'Cargo Collective' : '404 Not Found',
        'Digital Ocean' : 'Domain uses DO name serves with no records in DO.',
        'Fastly' : 'Fastly error: unknown domain:',
        'Feedpress' : 'The feed has not been found.',
        'Fly.io' : '404 Not Found',
        'Gemfury' : '404: This page could not be found.',
        'Ghost' : 'The thing you were looking for is no longer here, or never was',
        'Github' : 'There isn\'t a Github Pages site here.',
        'HatenaBlog' : '404 Blog is not found',
        'Help Juice' : 'We could not find what you\'re looking for.',
        'Help Scout' : 'No settings were found for this company:',
        'Heroku' : 'No such app',
        'Intercom' : 'Uh oh. That page doesn\'t exist.',
        'JetBrains' : 'is not a registered InCloud YouTrack',
        'Kinsta' : 'No Site For Domain',
        'LaunchRock' : 'It looks like you may have taken a wrong turn somewhere. Don\'t worry...it happens to all of us.',
        'Microsoft Azure' : ' ',
        'Netlify' : ' ',
        'Ngrok' : 'Tunnel *.ngrok.io not found',
        'Pantheon' : '404 error unknown site!',
        'Pingdom' : 'This public report page has not been activated by the user',
        'Readme.io': 'Project doesnt exist... yet!',
        'Shopify' : 'Sorry, this shop is currently unavailable.',
        'SmartJobBoard' : 'This job board website is either expired or its domain name is invalid.',
        'Statuspage' : 'redirect',
        'Strikingly' : 'page not found',
        'Surge.sh' : 'project not found',
        'Tumblr' : 'Whatever you were looking for doesn\'t currently exist at this address',
        'Tilda' : 'Please renew your subscription',
        'Uberflip' : 'Non-hub domain, The URL you\'ve accessed does not provide a hub.',
        'Uptimerobot' : 'page not found',
        'UserVoice' : 'This UserVoice subdomain is currently available!',
        'Wordpress' : 'Do you want to register *.wordpress.com?',
        'Worksites' : 'Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist.'
    }

    service = ''

    d_keys = list(domains.keys())
    d_vals = list(domains.values())

    for tld in d_vals:
        for d in tld:
            if d in cname:
                service = d_keys[d_vals.index(tld)]

    url = 'http://' + host
    try:
        r = requests.get(url).text
        if fingerprints[service] in r:
            return True
        else:
            return False
    except Exception as e:
        logger.error(e)


results = []
redundant = dict()

def threader():
    item = []
    while True:
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
            if 'A' in dns_info.keys():
                logger.warning(u'No ports were found open on \u001b[32;1m{}\u001b[0m'.format(host))
                item.append(host)
                item.append(dns_info['A'])
                item.append('')
            else:
                logger.warning(u'The DNS query for \u001b[32;1m{}\u001b[0m did not return any A record'.format(host))
                if 'CNAME' in dns_info.keys():
                    if takeoverCheck(host) == True:
                        logger.critical(u'Subdomain takeover may be possible on \u001b[32;1m{}\u001b[0m'.format(host)) 
                        item.append(host)
                        item.append(dns_info['CNAME'])
                        item.append('')
                    else:
                        item.append(host)
                        item.append('')
                        item.append('')
                else:
                    item.append(host)
                    item.append('')
                    item.append('')
        q.task_done()
        results.append(item)
        


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
            logger.critical('Maximum threads exceeded (20)')
            sys.exit()
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
