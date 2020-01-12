#!/usr/bin/python3

import os.path, sys, subprocess, getopt, os, re
from os import path

print("hello world")

print("checking for dependencies..")

def nmapchecker():
	print("file exists: " + str(path.exists('/usr/share/nmap/scripts/vulners.nse')))
	a = str(path.exists('/usr/share/nmap/scripts/vulners.nse'))
	print(a)
	if a == True:
		print("shit exists")
	else:
		b = subprocess.check_output(['sudo', 'git', 'clone', 'https://github.com/vulnersCom/nmap-vulners.git'])
		print(b)
		print("setting up vulners")
		subprocess.run(["sudo cp nmap-vulners/vulners.nse /usr/share/nmap/scripts/vulners.nse"])
		subprocess.check_output(["sudo cp nmap-vulners/http-vulners-paths.txt /usr/share/nmap/nselib/data/http-vulners-paths.txt"])
		subprocess.check_output(["sudo cp nmap-vulners/http-vulners-paths.json /usr/share/nmap/nselib/data/http-vulners-paths.json"])

def pipstuff():
	print("setting up pip required")
	subprocess.check_output(["sudo pip3 install -r requirements.txt"])
 
print("done")

nmapchecker()	
pipstuff()