#!/usr/bin/python3

import sys, subprocess, getopt, os, re, json


def jsonparser2():
    print("agfihiurghisreiv")
    with open('/tmp/scan.json', 'r') as r:
        data = json.load(r)
    #print(json.dumps(data, indent = 4, sort_keys=True))
    lenof1 = len(json.dumps(data['invalid_targets']))
    print(lenof1)
    if lenof1 > 5:
        print("empty")
    else:
        print(json.dumps(data['accepted_targets'][0]['commands_results']['fallback']['supports_fallback_scsv']))
    #for i in data:
        #if len(json.dumps(data['invalid_targets'])) < 3:
       #     print("empty")
      #      break
     #   else:
    #        print(len(json.dumps(data['accepted_targets'][0]['commands_results']['fallback']['supports_fallback_scsv'])))
    #print(len(json.dumps(data['invalid_targets'])))
    #print(len(json.dumps(data['accepted_targets'][0]['commands_results']['fallback']['supports_fallback_scsv'])))

def jsonparser():
    print("agfihiurghisreiv")
    with open('/tmp/scan.json', 'r') as r:
        data = json.load(r)
    #print(json.dumps(data, indent = 4, sort_keys=True))
    print(json.dumps(data['invalid_targets'][0]['invalid_targets']))
    print(json.dumps(data['accepted_targets'][0]['commands_results']['fallback']['supports_fallback_scsv']))
    #print(data['accepted_targets'][0]['commands_results']['heartbleed']['is_vulnerable_to_heartbleed'])
    #print(data['accepted_targets'][0]['commands_results']['openssl_ccs']['is_vulnerable_to_ccs_injection'])
    #print(data['accepted_targets'][0]['commands_results']['sslv2']['accepted_cipher_list'])
    #print(data['accepted_targets'][0]['commands_results']['sslv3']['accepted_cipher_list'])
    #print(data['accepted_targets'][0]['commands_results']['tlsv1']['accepted_cipher_list'])
    #print(data['accepted_targets'][0]['commands_results']['tlsv1_1']['accepted_cipher_list'])
    #print(data['accepted_targets'][0]['commands_results']['tlsv1_2']['accepted_cipher_list'])
    #print(data['accepted_targets'][0]['commands_results']['tlsv1_3']['accepted_cipher_list'])
    #print(data['accepted_targets'][0]['server_info'])

jsonparser2()
#jsonparser()