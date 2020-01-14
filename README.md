# Dovulsca
Domain Vulnerability Scanner - list vuln, spoof check, ssl, rank

**What is it?**

Dovulsca is a quick and dirty vulnerability scanner that will take the following steps:

  * SSLyze
  * Nmap
  * CVE correlation via [nmap-vulners](https://github.com/vulnersCom/nmap-vulners)
  * Extremely rootimentary grading system (this will change in future releases)
  * Display results per domain in wanna-be pretty format
  
**Dependencies**

 * Go install [nmap-vulners](https://github.com/vulnersCom/nmap-vulners)
 * PiP install requirements
   * colorama
   * emailprotectionslib
   * dnslib
   * tldextract
 * Alternatively use setup.py script and figure it out (its currently broken, needs to be fixed and updated)
 
 **Usage**
 
 ![Example](/example.jpg)
