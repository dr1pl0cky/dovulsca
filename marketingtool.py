import sys, subprocess, getopt, nmap, whois, os, re
target = sys.argv[1]
#target = raw_input("Enter the domain you would like to check: ")
#target = "tbconsulting.com"
def Primary():
	
	TLSv11 = False
	heartbleed = False
	scsv = False
	Grade = 0
	counter = 0

#	print("\nChecking for whois records...")
#	domain = whois.query(target)
#	print(domain.name + "\n")

	print("Checking for  nslookup...")
	process = subprocess.check_output(['nslookup', target])
#	output = process.splitlines()
#	ips = []
	ips = re.findall(r"Address: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", process)
	grades = []
	for ip in ips:
		#if re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", data)
		#if 'Address' in data:
		#	ips.append(data.replace("Address: " , ""))
			grades.append(100)
	print ips

	print("\nScanning TLS/SSL Configurations...")
	for IP in ips:
		
		command = "sslscan "+IP
		ciphers = subprocess.check_output(command.split())
		for line in ciphers.splitlines():
			if "Accepted" in line:
				line.split()[1]
				print(line.split()[1])
				if "TLSv1.1" in line and not TLSv11:
					grades[counter]= grades[counter] - 20
					TLSv11 = True
				if "TLSv1.0" in line and not TLSv11:
					grades[counter]= grades[counter] - 20
					TLSv11 = True
				if "SSLv2" in line and not TLSv11:
                                        grades[counter]= grades[counter] - 20
                                        TLSv11 = True
				if "SSLv3" in line and not TLSv11:
                                        grades[counter]= grades[counter] - 20
                                        TLSv11 = True
				

			if "heartbleed" in line:
				print(line)
			if "supports" in line:
				print(line)
			if "Server" in line and " TLS Fallback SCSV" in line and "not" in line:
				print(line)
				grades[counter]= grades[counter] - 10
		TLSv11 = False
		counter = counter + 1
	
	
#	print("\nRunning SYN scan on top 1000 common ports. This may take a while...")
#	
#	for i in ips:
#		print i, ":"
#		nmap = subprocess.check_output(['nmap','-Pn', i])
#		nmapoutput = nmap.splitlines()
#		for lines in nmapoutput:
#			if "open" in lines:
#				print lines
#			if "Host seems down" in lines:
#				print lines
#		print "\n"


#	nm = nmap.PortScanner()
#	for i in ips:
#		nm.scan(i)
#		print(nm.csv())
	
	outputs = subprocess.check_output('python spoof.py ' + target, shell=True)
	outputs.split('\n')

	

	print("\n----------------------------------")
	for i in range(len(grades)):
		Grade = Grade +  grades[i]
		
	total = float(len(grades)*100)
	print grades
	totalgrade = (Grade / total) * 100	
	print "Domain: ", target
	for lines in outputs.split('\n'):
		if "Spoofing possible" in lines:
			totalgrade = totalgrade - 10
        	if "poofing" in lines:
        		print(lines)
	print "Grade: ", totalgrade, "/100"


Primary()

 
