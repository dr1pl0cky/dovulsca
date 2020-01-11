#!/usr/bin/python3

import sys, subprocess, getopt, os, re, json, xml.etree.ElementTree as ET

def xmlparse4():
    a = ET.parse('/tmp/nmap.xml')
    b = a.getroot()
    #print(b)
    #print(b.tag)
    #print(b.attrib)
    #print(b[0].text)
    #print(b.iter('elem'))
    #print("rga984hrg08wrghfdjkghn3q9rg8u9irughpa89rhqg9rh4p9g")
    for d in b.iter('script'):
        #print(d.attrib)
        #print(d.items)
        print("DEBUG")
        g = d.attrib
        print(str(g))
        h = str(g)
        ab =re.findall(r'CVE\-\d{4}\-\d{1,8}', h)
        print(ab)
    print("########################")
    #print(b.iter('script'))
    
    print("########################")
    ab =re.findall(r'CVE\-\d{4}\-\d{1,8}', h)
    print(ab)


def xmlparse2():
    tree = ET.parse('/tmp/nmap.xml')
    root = tree.getroot()
    for child in root:
        testing = child.get('elem')
        if testing == 'script':
            print(child.tag, child.attrib)
            print(child.find('cvss').text)

def xmlparse3():
    tree = ET.parse('/tmp/nmap.xml')
    root = tree.getroot()
    for child in root.findall('.//table'):
        for schild in child.getchildren():
            #print(schild.tag, schild.attrib, schild.text)
            sd = schild.text
        print(sd)
        #print(list[schild.text])
            #print(schild.attrib, schild.text)
            #print("test test test")
            #print(schild.text)
            #df = df.replace('\r','')
            #df1 = re.sub('\w,', '', df)
            #print(df1)
            #ab = re.findall(r'CVE\-\d{4}\-\d{1,8}', schild.text)
            #print(ab)
            #ab2 = str(ab)
            #ab3 = re.sub('\n', '', ab2)
            #print(ab3)

def xmlparse():
    tree = ET.parse('/tmp/nmap.xml')
    root = tree.getroot()
    for child in root.findall('.//table'):
        for schild in child.getchildren():
            sd1 = (schild.tag, schild.attrib, schild.text)
            #sd = schild.tag
        #print(sd)
        #print(sd1)
        sd2 = str(sd1)
        sd3 = re.findall(r'CVE\-\d{4}\-\d{1,8}', sd2)
        print(sd3)



#xmlparse3()
#xmlparse2()
xmlparse()