#!/usr/bin/env python
# Author: Chris Duffy
# Date: June 4, 2014
# Email: Chris.Duffy@KnowledgeCG.com
# Credit: Shawn Evans for netcider.py, which the cidr class was extracted and slightly modified
# Email: Shawn.Evans@KnowledgeCG.com
'''
 Purpose: This script is designed to provide teams the means to quickly generate useful code for assessments.
 All the specific nuances of IP imports, file parsing and so forth have been handled so that an tester can just
 generate the needed code.
'''
# Some of these libraries are not needed
import sys
import operator
import itertools
import fileinput
import socket
import time
import datetime
import select
import re
import struct
import errno
from optparse import OptionParser
import xml.etree.ElementTree as etree

try:
    from functools import *
except:
    pass

class cidr():
    def __init__(self, address):
    
        try:
            index = address.index('/')
            self.base = address[:index]
            intMask = address[index+1:]
            self.netmask = self.netmask(intMask)
            self.wildcard = self.wildcard(intMask)
            self.binBase = self.addressToBin(self.base)    
            self.subnet = self.listToString(self.network(self.base, self.netmask))
            self.hostmin = self.hostMin(self.subnet)
            self.hostmax = self.hostMax(self.subnet, self.wildcard)
            self.total = self.numhosts(self.wildcard)
            self.broadcast = self.hostMin(self.hostmax)
            self.allips = self.getIpList(self.hostmin, self.hostmax) 
        except Exception as e:
            print(e) 
    
    def update(self, address):
        try:
            index = address.index('/')
            self.base = address[:index]
            intMask = address[index+1:]
            self.netmask = self.netmask(intMask)
            self.wildcard = self.wildcard(intMask)
            self.binBase = self.addressToBin(self.base)    
            self.subnet = self.listToString(self.network(self.base, self.netmask))
            self.hostmin = self.hostMin(self.subnet)
            self.hostmax = self.hostMax(self.subnet, self.wildcard)
            self.total = self.numhosts(self.wildcard)
            self.broadcast = self.hostMin(self.hostmax)
            self.allips = self.getIpList(self.hostmin, self.hostmax) 
        except Exception as e:
            print(e) 
    
    def toString(self):
        print ('Base:\t\t%s') % self.base
        print ('Netmask:\t%s') % self.netmask
        print ('Wildcard:\t%s') % self.wildcard
        print ('Broadcast:\t%s') % self.broadcast
        print ('Subnet ID:\t%s') % self.subnet
        print ('Host min:\t%s') % self.hostmin
        print ('Host max:\t%s') % self.hostmax
        print ('Total Hosts:\t%s') % self.total
    
    def getIpList(self, hostmin, hostmax):
        tmpmin = hostmin.split('.')
        tmpmax = hostmax.split('.') 
        ranges = [ range(i, j + 1) for i, j in zip(list(map(int, tmpmin)),list(map(int, tmpmax))) ]
        complete = [] 
        for ip in itertools.product(*ranges):
            complete.append( '.'.join(list(map(str, list(ip)))))
        return complete

    def numhosts(self, wildcard):
        tmpWild = list(map(int, wildcard.split('.')))
        ranges = list(map(lambda e: len(range(0, e + 1)), tmpWild))
        numhosts = reduce(operator.mul, ranges)-2
        return numhosts if numhosts > 0 else 1        

    def hostMin(self, address):
        temp = address.split('.')
        temp[3] = str(int(temp[3])+1)
        return self.listToString(temp)  
    
    def hostMax(self, address, wildcard):
        tmpAddr = address.split('.')
        tmpWild = wildcard.split('.')
        tmpWild[3] = str(int(tmpWild[3])-1)
        return self.listToString(list(map(sum, zip(list(map(int, tmpAddr)), list(map(int, tmpWild))))))
        
    def netmask(self, mask):
        binMask = '%s%s' % ('1'*int(mask), '0'*(32-int(mask)))
        maskList = list(map(''.join, zip(*[iter(binMask)] * 8)))
        netmask = self.binToAddress(maskList)
        return self.listToString(netmask)
        
    def wildcard(self, mask):
        binMask = '%s%s' % ('1'*int(mask), '0'*(32-int(mask)))
        maskList = list(map(''.join, zip(*[iter(binMask)] * 8)))
        netmask = self.binToAddress(maskList)
        wildcard = [ 255-val for val in netmask ]
        return self.listToString(wildcard)
 
    def listToString(self, ipList):
        return list(map('.'.join, [ list(map(str, ipList))] ))[0]
   
    def network(self, address, netmask):
        binNetwork = [ bin(int(a,2) & int(b,2))[2:].zfill(8) for a, b in zip(self.addressToBin(address), self.addressToBin(netmask))]
        return self.binToAddress(binNetwork)
     
    def addressToBin(self, address):
        return [ bin(int(val))[2:].zfill(8) for val in address.split('.') ]
    
    def printList(self):
        try:
            for ip in self.allips:
                print(ip)
        except Exception as e:
            print(e)
    
    def returnData(self):
        # Created a controlled return method for netcider (cduffy)
        try:
             return self.allips
        except Exception as e:
            print(e)

    def binToAddress(self, binAddress):
        return [ int(val,2) for val in binAddress ]
    
class Proto:
    def __init__(self):
        print ("[*] Code Prototyper")

    def uniq_list(self, import_list):
        # Uniques and sorts any list passed to it
        # Input: list
        # Returned: unique and sorted list
        set_list = set(import_list)
        returnable_list = list(set_list)
        returnable_list.sort()
        return (returnable_list)

    def unique_dict(self, verbose, hosts):
        # Uniques values in a dictionary
        # Input: Dictionary of hosts
        # Returned: Any uniqued dictionary
        temp = [(k, hosts[k]) for k in hosts]
        temp.sort()
        hosts={}
        for k, v in temp:
            if v in hosts.values():
                continue
            hosts[k] = v
        return (hosts)

    def get_date_time(self):
        # Generates a date time stamp.
        # Input: None
        # Returned: Time stamp in yyyy_mm_dd_HH_MM_SS string format
        timestamp = time.time()
        file_time_stamp = datetime.datetime.fromtimestamp(timestamp).strftime('%Y_%m_%d_%H_%M_%S')
        return (file_time_stamp)
    
    def scap_parser(self, verbose, scap_xml):
        # Parse the SCAP xml file and extract hosts and place them in a dictionary
        # Input: SCAP XML file and verbose flag
        # Return: Dictionary of hosts [iterated number] = [hostname, address, protocol, port, service name]
        if not scap_xml:
            sys.exit("[!] Cannot open SCAP XML file: %s \n[-] Ensure that your are passing the correct file and format" % (scap_xml))       
        try:
            tree = etree.parse(scap_xml)
        except:
            sys.exit("[!] Cannot open SCAP XML file: %s \n[-] Ensure that your are passing the correct file and format" % (scap_xml))       
        hosts={}
        services=[]
        root = tree.getroot()
        hostname_node = None
        if verbose >1:
            print ("[*] Parsing the SCAP XML file: %s") %(scap_xml)
        for host in root.iter('nodes'):
            hostname = "Unknown"
            service ="Unknown"  
            address = host.find('node').get('address')
            for name in host.iter('names'):
                try:        
                    hostname = name.find('name').text
                except:
                    if verbose>2:
                        print ("[-] No hostname found")
            for item in host.iter('endpoints'):
                for openport in item.iter('endpoint'):
                    state = openport.get('status')
                    if state.lower() == 'open':
                        protocol = openport.get('protocol')
                        port = openport.get('port')
                        service = openport.find('services').find('service').get('name')
                        service = service.lower()
                    services.append([hostname,address,protocol,port,service])
        for i in range(0, len(services)):
            service = services[i]
            hostname=service[0]
            address=service[1]
            protocol=service[2]
            port=service[3]
            serv_name=service[4]
            hosts[i]=[service[0],service[1],service[2],service[3],service[4]]
            if verbose >0:
                print ("[+] Adding %s with an IP of %s:%s with the service %s to the potential target pool") % (hostname,address,port,serv_name)
        if hosts:
            if verbose > 2:      
                print ("[*] Results from SCAP XML import: %s") % (hosts)
            return hosts
            if verbose > 0:
                print ("[+] Parsed and imported %s unique ports") % (str(i))
        else:
            if verbose > 0:
                print ("[-] No ports were discovered in the XML file")

    def nmap_parser(self, verbose, nmap_xml):
        # Parse the nmap xml file and extract hosts and place them in a dictionary
        # Input: Nmap XML file and verbose flag
        # Return: Dictionary of hosts [iterated number] = [hostname, address, protocol, port, service name]
        if not nmap_xml:
            sys.exit("[!] Cannot open Nmap XML file: %s \n[-] Ensure that your are passing the correct file and format" % (nmap_xml))       
        try:
            tree = etree.parse(nmap_xml)
        except:
            sys.exit("[!] Cannot open Nmap XML file: %s \n[-] Ensure that your are passing the correct file and format" % (nmap_xml))       
        hosts={}
        services=[]
        root = tree.getroot()
        hostname_node = None
        if verbose > 1:
            print ("[*] Parsing the Nmap XML file: %s") %(nmap_xml)
        for host in root.iter('host'):
            hostname = "Unknown"    
            address = host.find('address').get('addr')
            try: 
                hostname_node = host.find('hostnames').find('hostname')
            except:
                if verbose>2:
                    print ("[!] No hostname found")
            if hostname_node is not None:
                hostname = hostname_node.get('name')
            for item in host.iter('port'):
                state = item.find('state').get('state')
                if state.lower() == 'open':
                    service = item.find('service').get('name')
                    protocol = item.get('protocol')
                    port = item.get('portid')
                    services.append([hostname,address,protocol,port,service])
        for i in range(0, len(services)):
            service = services[i]
            hostname=service[0]
            address=service[1]
            protocol=service[2]
            port=service[3]
            serv_name=service[4]
            hosts[i]=[service[0],service[1],service[2],service[3],service[4]]
            if verbose > 0:
                print ("[+] Adding %s with an IP of %s:%s with the service %s to the potential target pool")%(hostname,address,port,serv_name)
        if hosts:
            return hosts    
            if verbose > 0:
                print ("[+] Parsed and imported unique ports") % (str(i))
        else:
            if verbose > 0:
                print ("[-] No ports were discovered in the XML file")

    def nmap_data(self, verbose, nmap_list):
        # Processes a list of NMAP XMls, which are passed to the parser
        # Input: List of NMAP XMLs
        # Returned: Composite dictionary of hosts [iterated number] = [hostname, address, protocol, port, service name]
        hosts = {}
        for xml in nmap_list:
            if verbose > 0:
                print ("[*] Processing Nmap XML: %s") % (xml)
            hosts_temp = self.nmap_parser(verbose, xml)
            hosts = dict(hosts_temp.items() + hosts.items())
        return (hosts)

    def scap_data(self, verbose, scap_xml):
        # Processes a list of SCAP XMls, which are passed to the parser
        # Input: List of SCAP XMLs
        # Returned: Composite dictionary of hosts [iterated number] = [hostname, address, protocol, port, service name]
        hosts={}
        for xml in scap_xml:
            if verbose > 0:
                print ("[*] Processing SCAP XML: %s") % (xml)
            hosts_temp = self.scap_parser(verbose, xml)
            hosts = dict(hosts_temp.items() + hosts.items())
        return (hosts)

    def targets_list_gen(self, verbose, ip, ip_list):
        # Generates fucntional ip list from imported string
        # Input: Verbosity level, ip string, ip list for multi-option CLI support
        # Returned: IP_list=[]
        ip_list = ip.split(',')
        ip_list = self.uniq_list(ip_list)
        return (ip_list)
        
    def domains_list_gen(self, verbose, domains, domains_list):
        # Generates fucntional domains list from imported string
        # Input: Verbosity level, domains string
        # Returned: domains_list=[]
        if "," in domains:
            domains_list = domains.split(',')
        else:
            domains_list.append(domains)
        domains_list = self.uniq_list(domains_list)
        return (domains_list)

    def passwords_list_gen(self, verbose, passwords, passwords_list):
        # Generates fucntional password list from imported string
        # Input: Verbosity level, password string, passwords list for multi-option CLI support
        # Returned: password_list=[]
        if "," in passwords:
            passwords_list = passwords.split(',')
        else:
            passwords_list.append(passwords)
        passwords_list = self.uniq_list(passwords_list)
        return (passwords_list)

    def usernames_list_gen(self, verbose, usernames, usernames_list):
        # Generates fucntional username list from imported string
        # Input: Verbosity level, username string, usernames list for multi-option CLI support
        # Returned: username_list=[]
        if "," in usernames:
            usernames_list = usernames.split(',')
        else:
            usernames_list.append(usernames)
        usernames_list = self.uniq_list(usernames_list)
        return (usernames_list)

    def credentials_list_gen(self, verbose, credentials, usernames_list, passwords_list, credentials_dict):
        # Generates fucntional username list, password list, and credential dictionary from imported string
        # Input: Verbosity level, credentials string, and for multi-option CLI support usernames list, passwords list and credentials dictionary
        # Returned: username_list=[], password_list=[],credential_dict={}
        credentials_list_temp=[]
        if "," in credentials:
            credentials_list_temp = credentials.split(',')
        else:
            credentials_list_temp.append(credentials)
        for credential in credentials_list_temp:
            username,password = credential.split(':')
            usernames_list.append(username)
            passwords_list.append(password)
            credentials_dict[username]=[password]
        usernames_list = self.uniq_list(usernames_list)
        passwords_list = self.uniq_list(passwords_list)
        return (usernames_list,passwords_list,credentials_dict)

    def port_list_gen(self, verbose, ports):
        # Tests for the number of ports and splits them off the string, currently the script only can accept one port
        # Input: Verbosity level, ports string
        # Returned: return port_list=[]
        port_list=[]
        if "," in ports:
            port_list = ports.split(',')
        else:
            port_list.append(ports)
        port_list = self.uniq_list(port_list)
        return (port_list)

    def import_passwords(self, verbose, passwords_file, passwords_list):
        # Generate a passwords list from an imported file
        # Input: Verbosity level, passwords file, and for multi-option CLI support the passwords list
        # Returned: passwords_list=[]
        if verbose >0:
            print ("[*] Importing passwords from a flat file")
        with open(passwords_file,'r') as file_temp:
            for line in file_temp:
                passwords_list.append(line.rstrip())
                if verbose >1:
                    print ("[+] Importing %s as a password") % (line)
                if not line: continue
        passwords_list = self.uniq_list(passwords_list)
        return (passwords_list)

    def import_domains(self, verbose, domains_file, domains_list):
        # Generate a domains list from an imported file
        # Input: Verbosity level, domains file, and for multi-option CLI support the domains list
        # Returned: domains_list=[]
        if verbose >0:
            print ("[*] Importing domains from a flat file")
        with open(domains_file,'r') as file_temp:
            for line in file_temp:
                domains_list.append(line.rstrip())
                if verbose >1:
                    print ("[+] Importing %s as a domains") % (line)
                if not line: continue
        domains_list = self.uniq_list(domains_list)
        return (domains_list)

    def import_usernames(self, verbose, usernames_file, usernames_list):
        # Generate a username list from an imported file
        # Input: Verbosity level, usernames file, and for multi-option CLI support usernames list
        # Returned: usernamess_list=[]
        if verbose >0:
            print ("[*] Importing usernames from a flat file")
        with open(usernames_file,'r') as file_temp:
            for line in file_temp:
                usernames_list.append(line.rstrip())
                if verbose >1:
                    print ("[+] Importing %s as a username") % (line.rstrip())
                if not line: continue
        usernames_list = self.uniq_list(usernames_list)
        return (usernames_list)

    def import_credentials(self, verbose, credentials_file, usernames_list, passwords_list, credentials_dict):
        # Generates fucntional username list, password list, and credential dictionary from imported file
        # Input: Verbosity level, credentials file, and for multi-option CLI support usernames list, passwords list and credentials dictionary
        # Returned: username_list=[], password_list=[],credential_dict={}
        if verbose >0:
            print ("[*] Importing credentials form a flat file")
        with open(credentials_file,'r') as file_temp:
            for line in file_temp:
                username,password = line.split(':',1)
                usernames_list.append(username)
                passwords_list.append(password.rstrip())
                credentials_dict[username]=[password]
                if verbose >1:
                    print ("[+] Importing %s and %s") % (username,password)
        usernames_list = self.uniq_list(usernames_list)
        passwords_list = self.uniq_list(passwords_list)
        return (usernames_list, passwords_list, credentials_dict)

    def import_ips(self, verbose, ipfile, ip_list):
        # Generates fucntional ip list from imported file
        # Input: Verbosity level, ip file, and for multi-option CLI support ip list
        # Returned: ip_list=[]
        if verbose >0:
            print ("[*] Importing IP addresses from a flat file")
        with open(ipfile,'r') as file_temp:
            for line in file_temp:
                ip_list.append(line.rstrip())
                if verbose >1:
                    print ("[+] Importing %s as a target") % (line)
                if not line: continue
        ip_list = self.uniq_list(ip_list)
        return (ip_list)

    def nmap_list_gen(self, verbose, nmap_xml):
        # Generates fucntional ip list from imported string
        # Input: Verbosity level, nmap string
        # Returned: nmap_xml=[]
        nmap_list=[]
        if "," in nmap_xml:
            nmap_list = nmap_xml.split(',')
        else:
            nmap_list.append(nmap_xml)
        return (nmap_list)

    def scap_list_gen(self, verbose, scap_xml):
        # Generates fucntional ip list from imported string
        # Input: Verbosity level, nessus string
        # Returned: scap_xml=[]
        scap_list=[]
        if "," in scap_xml:
            scap_list = scap_xml.split(',')
        else:
            scap_list.append(scap_xml)
        return (scap_list)

    def xml_processors(self, verbose, nmap_list, scap_list):
        # Processes and combines the results from multiple XML imports
        # Input: verbose, a list of NMAP XMLs, and SCAP XMLs
        # Returned: Combined hosts dictionary
        nmap_hosts={}
        scap_hosts={}       
        hosts_dict = {}
        # Identify unique occurances between multiple xml imports
        if nmap_list:
            if verbose > 0:
                print ("[*] Processing Nmap XMLs")
                nmap_hosts = self.nmap_data(verbose, nmap_list)
        if scap_list:
            if verbose > 0:
                print ("[*] Processing SCAP XMLs")
                scap_hosts=self.scap_data(verbose, scap_list)
        if nmap_hosts:
            hosts_dict = dict(nmap_hosts.items() + hosts_dict.items())
        if scap_hosts:
            hosts_dict = dict(scap_hosts.items() + hosts_dict.items())
        if verbose > 0:
            print ("[*] Removing duplicates from parsed data")
        hosts_dict = self.unique_dict(verbose, hosts_dict)
	return (hosts_dict)

    def setters(self, verbose, ip, ipfile, passwords_file, credentials_file, usernames_file, usernames, passwords, credentials, port, sleep_value, timeout_value, domains, nmap_xml, scap_xml, domains_file): 
        # This method sets lists, dictionaries and specific variables based on the data passed to the script at runtime
        # This method consolidates any of the data passed to the script from either interpolation or the CLI
        # Input: The verbosity level, comma separated ip string, ip file, passwords file, credentials file, usernames file, comma separated usernames string, comma separated passwords string, comma separated credentials string with colons deliniating the username and password, a comma deliminated string of ports, a sleep and timeout value passed in human readable format, a comma separated list of domain names, a comma separated string of NMAP & SCAP XMLs
        # Returned: dictionary created from XML imports, domains list, ip list, passwords list, username list, dictionary of credentials, list of ports, sleep value, timeout value, list of NMAP XMLs, list of SCAP XMLs
        port_list=[]
        signatures=[]
        usernames_list=[]
        passwords_list=[]
        ip_list=[]
        ip_list_final=[]
        domains_list=[]
        credentials_dict={}
        nmap_list=[]
        scap_list=[]
        hosts_dict={}
        if nmap_xml:
            nmap_list = self.nmap_list_gen(verbose, nmap_xml)
        if scap_xml:
            scap_list = self.scap_list_gen(verbose, scap_xml)
        if domains:
            domains_list = self.domains_list_gen(verbose,domains, domains_list)
        if domains_file:
            domains_list = self.import_domains(verbose, domains_file, domains_list)
        if ip:
            ip_list = self.targets_list_gen(verbose,ip, ip_list)
        if ipfile:
            ip_list = self.import_ips(verbose, ipfile, ip_list)
        if passwords_file:
            passwords_list = self.import_passwords(verbose, passwords_file, passwords_list)
        if credentials_file:
            usernames_list,passwords_list,credentials_dict = self.import_credentials(verbose, credentials_file, usernames_list, passwords_list, credentials_dict)
        if usernames_file:
            usernames_list = self.import_usernames(verbose, usernames_file, usernames_list)
        if usernames:
            usernames_list = self.usernames_list_gen(verbose,usernames, usernames_list)
        if passwords:
            passwords_list = self.passwords_list_gen(verbose,passwords, usernames_list)
        if credentials:
            usernames_list,passwords_list,credentials_dict = self.credentials_list_gen(verbose,credentials, usernames_list, passwords_list, credentials_dict)
        if sleep_value:
            sleep_value = self.timeid(verbose, sleep_value)
        if timeout_value:
            timeout_value = self.timeid(verbose, timeout_value)
        if port:
            port_list = self.port_list_gen(verbose, port)
        else:
            port_list.insert(0,"")
	if nmap_list or scap_list:
		hosts_dict = self.xml_processors(verbose, nmap_list, scap_list)
        ip_list_final = self.cidrProcess(verbose, ip_list)
        return (hosts_dict, domains_list, ip_list_final, passwords_list, usernames_list, credentials_dict, port_list, sleep_value, timeout_value, nmap_list, scap_list)
    
    def timeid(self, verbose, time):
        # This parses the human readable version of time value and returns the seconds notation
        # Input: verbosity level and human readable time value
        # Returned: Seconds notation of the human readable format
        match = re.match(r"([0-9]+)([a-z]+)", time, re.I)
        if verbose >2:
            print ("[*] The time value being evaluated is: %s") % (time)
        if match:
            items = match.groups()
            if "ms" in items[1]:
                if verbose >2:
                    print ("[*] Time value %s milliseconds") % (items[0])
                denom=1000
                numerator=items[0]
                numerator = int(numerator)
                denom = int(denom)          
                try:
                    time = numerator/denom
                except:
                    sys.exit("[!] An incorrect time standard was selected") 
            elif "s" in items[1]:
                if verbose >2:
                    print ("[*] Time value %s seconds") % (items[0])
                denom=1
                numerator=items[0]
                numerator = int(numerator)
                denom = int(denom)          
                try:
                    time = numerator/denom
                except:
                    sys.exit("[!] An incorrect time standard was selected") 
            elif "m" in items[1]:
                if verbose >2:
                    print ("[*] Time value %s minutes") % (items[0])
                numerator = 60
                denom=items[0]
                numerator = int(numerator)
                denom = int(denom)          
                try:
                    time = numerator/denom
                except:
                    sys.exit("[!] An incorrect time standard was selected") 
            elif "h" in items[1]:
                if verbose >2:
                    print ("[*] Time value %s hours") % (items[0])
                time = item[0]*3600
            if verbose >2:
                print ("[*] Time value in Seconds: %d") % (time)
        return (time)
        
    def output_data(self, verbose, directory, ip, port, data, filename):
        # Outputs data from each test case, creating a unique file for each system
        # Returned: Nothing only STDOUT
        current_time = self.get_date_time()
        if filename:
            output_file = "%s/ip_%s_port_%s_result_%s" % (directory, ip, port, filename)
        else:   
            output_file = "%s/ip_%s_port_%s_result_%s" % (directory, ip, port, current_time)
        if verbose >0:
            print ("[*] Writing the information to %s") % (output_file)
        with open(output_file,'a') as file_temp:
            if data is list:
                for item in data:
                    item = item+"\n"
                    file_temp.write(item)
            if data is dict:
                for key, value in data.iteritems():
                    item = key+":"+value
                    file_temp.write(item)
            if data is str:
                data = data+"\n"
                file_temp.write(item)
        self.unique_filecontents(verbose, output_file)

    def output_master(self, verbose, directory, data, filename):
        # Outputs data from the final test case, creating a master output file for each data type input
        # Input: Verbosity level, output directory, data type, title name of output file
        # Returned: Nothing only STDOUT
        current_time = self.get_date_time()
        if filename:
            output_file="%s/%s" % (directory, filename)
        else:       
            output_file = "%s/proto_%s" % (directory, current_time)
        if verbose >0:
            print ("[*] Exporting master data results from analysis")
            print ("[*] Writing the information to %s") % (output_file)
        with open(output_file,'a') as file_temp:
            if data is not str:
                for item in data:
                    item = item+"\n"
                    file_temp.write(item)
            else:
                data = data+"\n"
                file_temp.write(data)
        self.unique_filecontents(verbose, output_file)

    def unique_filecontents(self, verbose, filename):
        # Ensures that any data added to file results are unique
        # Input: verbosity level and the filename
        # Returned: None
        infile = open(filename,"r")
        wordsDict = {}
        for line in infile:
            addBoolean = True
            for word in wordsDict:
                if word == line:
                    addBoolean = False
                    break
            if addBoolean:
                wordsDict[line] = None
        infile.close()
        outfile = open(filename,"w")
        for word in wordsDict:
            outfile.write(word+'\n')

    def get_date_time(self):
        # Generates a date time stamp.
        # Input: None
        # Returned: Time stamp in yyyy_mm_dd_HH_MM_SS string format
        timestamp = time.time()
        file_time_stamp = datetime.datetime.fromtimestamp(timestamp).strftime('%Y_%m_%d_%H_%M_%S')
        return (file_time_stamp)
            
    def cidrProcess(self, verbose, ip_list):
        # Interacts with the netcider class to process CIDR noted IP addresses
        # Input: verbosity and Ip list
        # Returned: A unique and sorted list of IP addresses
        cidrIP=[]
        cidrData=[]
        for ip in ip_list:
            if "/" in ip:
                cidrIP.append(cidr(ip))
            else:
                cidrData.append(ip)
        for cidrItem in cidrIP:
            cidrData.extend(cidrItem.returnData())
            cidrData = self.uniq_list(cidrData)
        return (cidrData)
        
    def yourTool(self, verbose, usernames_list, passwords_list, credentials_dict, ip_list, timeout_value, sleep_value, port_list, output_dir, filename, domains_list, hosts_dict):
        # This function will define the rest of your tool the following items are passed to the fuction
        # verbose = a value that has an unlimited range and starts at 1 by default, at 0 it is quiet
        # usernames_list = a list of usernames passed via either command line or parsed file
        # passwords_list = a list of passwords passed via either command line or parsed file
        # credentials_dict = a dictionary of usernames with the username as the key and the password as the value,
        # these are passed by either command line or file with a colon seperating the values
        # ip_list = a list of IP addresses that have been parsed from either the command line or file
        # timeout_value = a value in seconds that was processed from a human readable input, used for timing out connections
        # sleep_value = a value in seconds that was processed from a human readable input, used for sleeping between connections
        # port_list = a list of ports that can be tested
        # ouptut_dir = am optional directory to output data
        # filename = an optional filename that will be used to output results
        # domains_list = A list of domain names
        # hosts_dict = Composite dictionary of hosts [iterated number] = [hostname, address, protocol, port, service name]
        valid={}
        ###### YOUR PROCESS: ADD CODE ######
        if verbose > 0:
            print ("[*] Customize proto.py to fit the specific need")
        ###### OUTPUT YOUR DATA: ADD CODE ######
        #Output for specific instances of valid data
        #self.output_data(verbose, output_dir, ip, port, valid, filename)
        return (valid)

    def main(self):
        # Create options and usage statement for CLI if the script is called on its own
        usage = '''usage: %prog [-i ip,cidr] [-I ipfile] 
        [-u user1,user2] [-U user_file] [-p pass1,pass2]
        [-P pass_file] [-c user1:pass1,user2:pass2] 
        [-C cred_file] [--port port1,port3] [--sleep 100ms]
        [--timeout 100ms] [-o /output/dir] [-f filename] 
        [-d DOMAIN] [--nmap_xml test.xml] [--scap_xml reports.xml]
        -q -v -vv -vvv'''
        parser = OptionParser(usage=usage, version='0.42b')
        parser.add_option("-i", "--ip", help="IP address or FQDN of the target", action="store", type="string", dest="ip")
        parser.add_option("-I", "--ip_file", help="IP address or FQDN of the target", action="store", type="string", dest="ipfile")
        parser.add_option("-u", "--usernames", help="Username tests", action="store", dest="usernames") 
        parser.add_option("-U", "--usernames_file", help="The username wordlist", action="store", type="string", dest="usernames_file")
        parser.add_option("-p", "--passwords", help="Password tests", action="store", dest="passwords")
        parser.add_option("-P", "--passwords_file", help="Password file with password on each line", action="store", dest="passwords_file")
        parser.add_option("-c", "--credentials", help="Input credential test username:password", action="store", dest="credentials")
        parser.add_option("-C", "--credentials_file", help="Input multiple credentials with username:password on every line ", action="store", dest="credentials_file")
        parser.add_option("--nmap_xml", help="Test targets from a recent nmap XML file output", action="store", dest="nmap_xml")
        parser.add_option("--scap_xml", help="Test targets from a SCAP XML output file from VA tools such as Nexpose or Nessus, multiple files can be referenced by seperating entries with commas", action="store", dest="scap_xml")
        parser.add_option("-d", "--domain", help="Input multiple domains separated by commas", action="store", dest="domains")
        parser.add_option("-D", "--domain_file", help="Input multiple domains separated by new lines", action="store", dest="domains_file")
        parser.add_option("--port", help="The Port Number, if one is not set the default will be used", action="store", default="", dest="port")
        parser.add_option("--sleep", help="Create a sleep time between connections: M=Minutes, H=Hours, S=Seconds, ms=milliseconds (i.e. 100ms)", action="store", default="0s", dest="sleep_value")
        parser.add_option("--timeout", help="Create a timeout value for lingering connections: M=Minutes, H=Hours, S=Seconds, ms=milliseconds (i.e. 100ms), default is 2 Seconds", action="store", default="2s", dest="timeout_value")
        parser.add_option("-o", "--output", help="The location to output the results, the default is /tmp", action="store", default="/tmp", dest="output_dir")
        parser.add_option("-f", "--filename", help="The part of the filename that identifies the session, if not set a timestamp will be appended", action="store", dest="filename")
        parser.add_option("-v", action="count", dest="verbose", default=1, help="Verbose, defaults to on, this outputs each command and result")
        parser.add_option("-q", action="store_const", dest="verbose", const=0, help="Sets the results to be quiet")
        (options, args) = parser.parse_args()
        
        # Set Constructors
        ip = options.ip                                 # IP option
        ipfile = options.ipfile                         # IP List option
        port = options.port                             # Port option
        usernames = options.usernames                   # Usernames string option
        usernames_file = options.usernames_file         # Usernames file option
        output_dir = options.output_dir                 # Ouput directory location
        filename = options.filename                     # Filename used to append 
        passwords_file = options.passwords_file         # Password file option
        domains_file = options.domains_file             # Domains file option
        credentials_file = options.credentials_file     # Credentials file option
        passwords = options.passwords                   # Passwords string option
        credentials = options.credentials               # Credentials string option
        domains = options.domains                       # Domains input
        verbose = options.verbose                       # Sets the verbosity level or if the value should be quiet
        sleep_value = options.sleep_value               # Sleep Value Between Connections
        timeout_value = options.timeout_value           # Timeout Value for Lingering Connections
        nmap_xml = options.nmap_xml                     # Nmap file input via CLI
        scap_xml = options.scap_xml                     # SCAP XML file input via CLI

        ## Process variables
        count=0                                         #Duh
        
        ## Products of setters
        targets_dict={}                                 # Targets generated for the connections
        port_list=[]                                    # Generated from port setter
        passwords_list=[]                               # Generated from password setters
        ip_list=[]                                      # Generated from IP setters
        usernames_list=[]                               # Generated from username setters
        domains_list=[]                                 # Generated from domains setters
        nmap_list=[]                                    # Generated from nmap setters
        scap_list=[]                                    # Generated from scap setters
        credentials_dict={}                             # Generated from credentials setters
        
        ## Final Data
        final ={}

        # Verifiers, Setters, and Generators
        hosts_dict, domains_list, ip_list, passwords_list, usernames_list, credentials_dict, port_list, sleep_value, timeout_value, nmap_list, scap_list = self.setters(verbose, ip, ipfile, passwords_file, credentials_file, usernames_file, usernames, passwords, credentials, port, sleep_value, timeout_value, domains, nmap_xml, scap_xml, domains_file)

        ###### YOUR PROCESS: CREATE A VALIDAOR TO ENSURE PROPER DATA IS PASSED VIA CLI ######

        ###### YOUR PROCESS: REMOVE DEBUG CODE ######
        # PRINT Data for Debugging
        if verbose > 0:
            print ("[*] IP List: %s") % (ip_list) #DEBUG
            print ("[*] Passwords List: %s") % (passwords_list) #DEBUG
            print ("[*] Usernames List: %s") % (usernames_list) #DEBUG
            print ("[*] Credentials Dictionary: %s") % (credentials_dict) #DEBUG
            print ("[*] Domains List: %s") % (domains_list) #DEBUG
            print ("[*] Port List: %s") % (port_list) #DEBUG
            print ("[*] Sleep Value: %s") % (sleep_value) #DEBUG
            print ("[*] Timeout Value: %s") % (timeout_value)#DEBUG
            print ("[*] Hosts dictionary from XML imports: %s") % (hosts_dict) #DEBUG
            print ("[*] List of NMAP XMLs: %s") % (nmap_list) #DEBUG
            print ("[*] List of SCAP XMLs: %s") % (scap_list) #DEBUG
        ###### YOUR PROCESS: MODIFY PARAMETERS AND RETURNS ######
        final = self.yourTool(verbose, usernames_list, passwords_list, credentials_dict, ip_list, timeout_value, sleep_value, port_list, output_dir, filename, domains_list, hosts_dict)
            
if __name__ == '__main__': Proto().main()   

