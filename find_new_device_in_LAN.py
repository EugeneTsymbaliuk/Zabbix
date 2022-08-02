#!/usr/bin/env python3

import time
from datetime import date, datetime
import requests
import json
from ise import ERS
import textfsm
import paramiko
import pyzabbix
import urllib3
import smtplib

# User Credentials
sender = 'zabbix@google.com'
receivers = ['simba@gooogle.com']
user = 'User'
passwd = 'Passw0rd'
api_user = 'apiUser'
api_passwd = 'APIPassw0rd'

# List of Devices
ip_list = ['10.10.10.108', '10.10.11.108']

# Send Mail Function
def send_mail(hostname, host_ip):
	message = """From: zabbix@google.com
To: Net Admins <simba@gooogle.com>
Subject: New device has been added on Zabbix

New device with hostname """ + hostname  + """ has been found on """ + host_ip + """ and added to n7zabbix for monitoring.
Do not forget to add this device on IPAM.

Yours Sincerely,
Zabbix
"""

	try:
		smtpObj = smtplib.SMTP('i0smtp01.google.com')
		smtpObj.sendmail(sender, receivers, message)
		print("Successfully sent email")
	except SMTPException:
		print("Error: unable to send email")

# Specify a Data Type for API
zabbix_headers = {'Content-type': 'application/json', 'Accept': 'text/plain', 'Content-Encoding': 'utf-8'}
ise_headers = {'Content-type': 'application/json', 'Accept': 'application/json', 'Content-Encoding': 'utf-8'}

# Disable SSL Certrification Warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# API Connect to Zabbix
z_conn = pyzabbix.ZabbixAPI('http://127.0.0.1/zabbix')
z_conn.login(api_user, api_passwd)

# Get hostnames from Zabbix
zabbix_hostnames = []
for h in z_conn.host.get(output="extend"):
	zabbix_hostnames.append(h['host'])

# Empty hostname list
hostname_list = []

# Connect do each device from ip_list
for ip in ip_list:
#	print(ip)
	try:
	#Logging into device
		session = paramiko.SSHClient()
	#For testing purposes, this allows auto-accepting unknown host keys Do not use in production! The default woul$
		session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	#Connect to the device using username and password
		session.connect(ip, username = user, password = passwd)
	#Start an interactive shell session on the router
		connection = session.invoke_shell()
	#Setting terminal length for entire output - disable pagination connection.send("terminal length 0\n") time.sl$
		connection.send("terminal len 0\n")
		time.sleep(1)
	#Send command
		connection.send("sh cdp neighbors detail | i ID:|ddress:\n")
		time.sleep(1)
	#Checking command output for IOS syntax errors
		router_output = connection.recv(65535)
	#Convert bytes into string
		router_output = router_output.decode("utf-8")
	#Closing the connection
		session.close()
		with open('sh_cdp_n_det.template') as template:
			fsm = textfsm.TextFSM(template)
			result = fsm.ParseText(router_output)
		for int_ip in result:
			hostname = int_ip[1].rstrip('.nbu{crp}.bank.gov.ua')
			if hostname not in zabbix_hostnames and hostname.startswith('n7'):
				try:
					# Set date and time for Device Description
					today = date.today()
					now = datetime.now()
					current_time = now.strftime("%H:%M:%S")

					# Add New Device On Zabbix
					add_host = z_conn.host.create(host=hostname, description= 'This device was added by script ' + str(today) + ' at ' + current_time, interfaces=[{'type': 2, 'main': 1, 'useip': 1, 'ip': int_ip[2], 'dns': '', 'port': '161', 'details': {'version': 2, 
							'community': 'catro'}}], groups=[{'groupid': '24'}], templates=[{'templateid': '10186'}], inventory_mode=-1)

					# Connect to ISE
					ise = ERS(ise_node='ISE_IP_Address', ers_user=api_user, ers_pass=api_passwd, verify=False, disable_warnings=True)

					# Add Device on ISE
					ise.add_device(name=hostname, ip_address=int_ip[2], radius_key='radius_key', snmp_ro='public', dev_group='test#test', dev_location='Location#All Locations#LAN Nauky',
							dev_type='Device Type#All Device Types#Switches_Grp')

					# Call Send Mail Function
					send_mail(hostname, ip)

				except pyzabbix.ZabbixAPIException:
					print('---------------------------------------')
					print('Host with the same name ' + hostname  + ' already exists on Zabbix!')
					print('---------------------------------------')

			elif hostname not in zabbix_hostnames and hostname.startswith('i9') or hostname.startswith('40') or hostname.startswith('34'):
				try:
                                        # Set date and time for Device Description
					today = date.today()
					now = datetime.now()
					current_time = now.strftime("%H:%M:%S")

                                        # Add New Device On Zabbix
					add_host = z_conn.host.create(host=hostname, description= 'This device was added by script ' + str(today) + ' at ' + current_time, interfaces=[{'type': 2, 'main': 1, 'useip': 1, 'ip': int_ip[2], 'dns': '', 'port': '161', 'details': {'version': 2,
									'community': 'catro'}}], groups=[{'groupid': '23'}], templates=[{'templateid': '10186'}], inventory_mode=-1)

                                        # Connect to ISE
					ise = ERS(ise_node='ISE_IP_Address', ers_user=api_user, ers_pass=api_passwd, verify=False, disable_warnings=True)

                                        # Add Device on ISE
					ise.add_device(name=hostname, ip_address=int_ip[2], radius_key='qazxsw', snmp_ro='public', dev_group='test#test', dev_location='Location#All Locations#LAN Instytutska',
							dev_type='Device Type#All Device Types#Switches_Grp')

                                        # Call Send Mail Function
					send_mail(hostname, ip)

				except pyzabbix.ZabbixAPIException:
					print('---------------------------------------')
					print('Host with the same name ' + hostname  + ' already exists on Zabbix!')
					print('---------------------------------------')
			elif hostname not in zabbix_hostnames:
				try:
                                        # Set date and time for Device Description
					today = date.today()
					now = datetime.now()
					current_time = now.strftime("%H:%M:%S")

                                        # Add New Device On Zabbix
					add_host = z_conn.host.create(host=hostname, description= 'This device was added by script ' + str(today) + ' at ' + current_time, interfaces=[{'type': 2, 'main': 1, 'useip': 1, 'ip': int_ip[2], 'dns': '', 'port': '161', 'details': {'version': 2,
							'community': 'catro'}}], groups=[{'groupid': '34'}], templates=[{'templateid': '10186'}], inventory_mode=-1)

                                        # Connect to ISE
					ise = ERS(ise_node='ISE_IP_Address', ers_user=api_user, ers_pass=api_passwd, verify=False, disable_warnings=True)

                                        # Add Device on ISE
					ise.add_device(name=hostname, ip_address=int_ip[2], radius_key='qazxsw', snmp_ro='public', dev_group='test#test', dev_location='Location#All Locations#Automated',
							dev_type='Device Type#All Device Types#Automated_Added_Grp')

                                        # Call Send Mail Function
					send_mail(hostname, ip)

				except pyzabbix.ZabbixAPIException:
					print('---------------------------------------')
					print('Host with the same name ' + hostname  + ' already exists on Zabbix!')
					print('---------------------------------------')

			else:
				pass
	except paramiko.ssh_exception.AuthenticationException:
		pass
#		print('WRONG PASSWORD!')
	except paramiko.ssh_exception.NoValidConnectionsError:
		pass
#		print('UNABLE TO CONNECT TO PORT 22 ON ' + ip)
	except TimeoutError:
		pass
