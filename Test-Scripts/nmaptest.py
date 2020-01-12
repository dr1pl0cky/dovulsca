#!/usr/bin/python3

import sys, subprocess, getopt, os, re, json, xml.etree.ElementTree as ET, xmltodict

def map():
    print("\nRunning NMAP scan on: ")
    subprocess.run(['sudo', 'nmap', '-sV', '--script', 'vulners', 'rocket.com'])

def xmlparse():

    # with open('/tmp/nmap.xml', 'r') as r:
    f = open("/tmp/nmap.xml")
    xml_content = f.read()
    f.close()
    #print(json.dumps(xmltodict.parse(xml_content), indent=4, sort_keys=True))

    nmap_results = xmltodict.parse(xml_content)

    #print(json.dumps(nmap_results['nmaprun']['host']['ports']['port']))
    a = (json.dumps(nmap_results['nmaprun']['host']['ports']['port']))
    #print(a)
    m = re.findall(r'@output\":\W\"\\n(?P<cve>.+),\W\"table\"\:\W\{\"\@key', a)
    print(m)
    #m.groups(1)
    #n.group('cve')
    #@output\":\W\"\\n(.+),\W\"table\"\:\W\{\"\@key
    #for script in nmap_results['nmaprun']['host']['ports']['port']['script']:
     #   if 'elem' in script['table']:
      #      elem = script['table']['elem']
       #     print(str(elem))
        #else:
         #   elem = "unknown"
        #print(script['@output'] + " - " + elem)
        # for line in r.readlines():
        #     if '<elem key="id">CVE' in line:
        #         a = line
        #         b = re.sub('<elem key="id">', '', a)
        #         c = re.sub('</elem>', '', b)
        #         d = re.sub('\n', '', c)
        #         print(d)

xmlparse()