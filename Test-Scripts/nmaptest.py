#!/usr/bin/python3

import sys, subprocess, getopt, os, re, json, xml.etree.ElementTree as ET

def map():
    print("\nRunning NMAP scan on: ")
    subprocess.run(['sudo', 'nmap', '-sV', '--script', 'vulners', 'rocket.com'])

def xmlparse():
    d = ""

    with open('/tmp/nmap.xml', 'r') as r:
        for line in r.readlines():
            if '<elem key="id">CVE' in line:
                a = line
                b = re.sub('<elem key="id">', '', a)
                c = re.sub('</elem>', '', b)
                d = re.sub('\n', '', c)
                print(d)
xmlparse()