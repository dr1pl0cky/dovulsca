# Dovulsca
Domain Vulnerability Scanner - list vuln, spoof check, ssl, rank
---
**What is it?**
---
Dovulsca is a quick and dirty vulnerability scanner that will take the following steps:

  * SSLyze
  * Nmap
  * Check if the domain is able to be spoofed (No SPF or DMARC)
  * CVE correlation via [nmap-vulners](https://github.com/vulnersCom/nmap-vulners)
  * Extremely rootimentary grading system (this will change in future releases)
  * Display results per domain in wanna-be pretty format
--- 
**Dependencies**
---
 * Go install [nmap-vulners](https://github.com/vulnersCom/nmap-vulners)
 * PiP install requirements
   * colorama
   * emailprotectionslib
   * dnslib
   * tldextract
 * Alternatively use setup.py script and figure it out (its currently broken, needs to be fixed and updated)
---
 **Usage**
--- 
 ![Example](/example.jpg)

```
python3 dovulsca.py [Domain]
```
To Do list
---
- [ ] Add colors and help menu 
- [ ] Fix IP grabber func: when more that one IP appears for domain, it will break
- [ ] Fix Grading: even though this is going away, still need to atleast make it more accurate for now
- [ ] Fix Nmap and SSLyze func: seems like 3/10-ish times this will return shit/odd results. Need to make this more stable. Maybe it's the lack of stop between store/parse/del ? 

