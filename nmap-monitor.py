#!/usr/bin/evn python
# 
# Name: nmap-monitor
# Description: Program that nmap scans a range, records results and notifies a webhook 
#              of changes. 
#              Note if not run as sudo/root it wil prompt for sudo creds interactively. 
#              If running from crontab, ensure it is root crontab.  
# Usage: python nmap-monitor.py [params]
# Params:   -t <CIDR> | range for scan e.g. 203.42.222.128/25
#           -f <filename> | filename for file that holds/will hold previous scan results
#           -w <webhook url> | notification webhook URL
#
# Author: Chris Pennycuick

__version__ = '0.1.0'

import nmap #https://pypi.org/project/python-nmap/
import os
import requests
import json
import argparse


# Main Method - Scans range specifed in parameters, and compares it to the previous scan and provides changes to specified webhook  
def main():

    # List to hold current, previous scan results and text for the notification
    currentScan = []
    previousScan= []
    notificationText = []

    print("...Starting python nMap monitor...")

    # Read CLI params in with defaults set for my purposes... 
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', type=str, default='203.42.222.128/25', help='CIDR range for nmap scan e.g. 203.42.222.128/25')
    parser.add_argument('-f', type=str, default='previousscan.txt', help='filename for file that holds/will hold previous scan results')
    parser.add_argument('-w', type=str, help='notification webhook URL', default="https://<company>.webhook.office.com/webhookb2/2ed80882-6243-dfda-b1ed-120bcc440047@556f4662-c7de-4312-9a81-dd4e68521c32/IncomingWebhook/eedaf056e5914d71aeb933a5a521a536/1b8114fe-ef4a-4512-b913-7df0fad0ffa0")
    args = parser.parse_args()

    # Scan the target
    currentScan = nmapscan(args.t)

    # Open the previous scan fingerprint list from the filename passed in on CLI. In this context Fingerprint is host port combo..  
    previousScan = loadPreviousScan(args.f)

    # Compare the previous scan and the current scan fingerprints
    # Identify removed ports
    removedPorts = list(get_difference(previousScan, currentScan))
    if len(removedPorts) > 0 :
        print("Removed Ports: ", removedPorts)
        notificationText.insert(0,"\nRemoved Ports: %s" % "\n".join(removedPorts))

    # Identify new open ports
    newPorts = list(get_difference(currentScan,previousScan))
    if len(newPorts) > 0 :
        print("New Ports: ", newPorts)
        notificationText.insert(0,"\nNew Ports: %s" % "\n".join(newPorts))

    # If there are changes send an alert to the MS Teams Channel specified in the CLI param.
    if len(newPorts)>0 or len(removedPorts)>0: 
        
        # Notification Webhook 
        url = args.w
        
        # Add the notification text to the payload
        payload = {
        "text": "\n".join(notificationText)
        }
        headers = {
            'Content-Type': 'application/json'
        }

        # sent the notification
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        print(response.text.encode('utf8'))

    #save the current scan results as the previous scan for the next run
    saveScan(currentScan, args.f)
        
    print("\n...python nMap monitor complete.\n")

# Method to save the finger prints of a scan results 
def saveScan(currentScan, filename):
    with open(filename, 'w') as filehandle:
        for listitem in currentScan:
            filehandle.write(f'{listitem}\n')

# Method to load fingerprints of the last scan results
def loadPreviousScan(filename):
    previousResults = []
    # Check to see if the file exists to avoid errors
    if os.path.exists(filename) :
        with open(filename, 'r') as filehandle:
            for line in filehandle:
                # Remove linebreak which is the last character of the string
                curr_place = line[:-1]
                # Add item to the list
                previousResults.append(curr_place)
    return previousResults

# Method to identify elements of list a that are not in list b
def get_difference(list_a, list_b):
    nonMatch = []
    for i in list_a:
        if i not in list_b:
            nonMatch.append(i)
    return nonMatch

# Method to run the portscan using the nmap library. 
# It then iterates the results to build the finger prints
def nmapscan(target):
    scan = []
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='--max-rtt-timeout 100ms -vv -sS', sudo=True)
    print("scan complete %s" % nm.command_line())
    
    # iterate scan results to built current scan finger print
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            for protocol in nm[host].all_protocols():
                ports = nm[host][protocol].keys()
                for port in ports:
                    if nm[host][protocol][port]['state'] == 'open' :
                        scan.append(str(host) + ':' + str(port) + ':' + nm[host][protocol][port]['state'])
    return scan

# Python line to get the show started... 
if __name__ == '__main__':
    main()
