# NMAP-MONITOR
Nmap-monitor is a simple Python script that uses nmap to scans a CIDR range, records results and notifies a webhook of changes. It requires Nmap to installed in on the underlying system. 

I wrote it because my base level Shodan would only monitor 16 IPs, and well I figured it wouldn't be too hard to setup a script and crontab for.

## Basic outline of program
1. Scans the passed in range using the underlying systems nmap with the options: --max-rtt-timeout 100ms -vv -sS
2. Opens the filename passed in to get previous results
3. Compares the current and previous results
4. Alerts a passed in web hook for new or removed port/IP combos
5. Saves the current scan as the previous for next time in the passed in filename

## Crontab
I set it up on RPI with a crontab. Please note if run from normal user it will prompt for sudo. So if running on Crontab, use root to avoid disapointment.  
### Example CronTab line
00 23	* *	*	root	cd /home/user/code/python/nmap-monitor/ && python /home/user/code/python/nmap-monitor/nmapmonitor.py

## Program Particulars
- name: nmap-monitor.py
- Usage: python nmap-monitor.py [params]
- Params:
    - -t <CIDR> | range for scan e.g. 203.42.222.128/25
    - -f <filename> | filename for file that holds/will hold previous scan results
    - -w <webhook url> | notification webhook URL

## Python Requirements
Requirements: 
- certifi==2022.12.7
- charset-normalizer==3.1.0
- idna==3.4
- python-nmap==0.7.1
- requests==2.28.2
- urllib3==1.26.15

## License
I don't imagine anyone else will use this... but if they do MIT License. 
