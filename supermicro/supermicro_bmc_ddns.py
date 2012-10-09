#!/usr/bin/python
# Aaron Knister <aaron.knister@gmail.com>

import subprocess
import re
import sys
import pexpect
import os

password=os.environ['BMC_PASSWORD']
node_name=sys.argv[1]
bmc_hostname=sys.argv[2]
bmc_username=sys.argv[3]

#logfile=open('logfile','w')
def get_bmc_ip_from_node(node_name):
	""" SSH to a node and use ipmitool to return the BMC's MAC address and current IP """

	mac_addr=None
	ip_addr=None

	s=subprocess.Popen(['ssh','-l','root',node_name,'ipmitool lan print'],
			stdin=None,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,shell=False)
	(stdout,stderr)=s.communicate()
	if not s.returncode == 0:
		raise Exception,"Failed to get BMC information from remote node.\noutput: %s" % (stdout)

	# Loop through each line, strip the newline and attempt to split into key/value pairs
	for line in stdout.split('\n'):
		try:
			key,value=line.split(':',1)
		except ValueError:
			continue

		# Find the MAC Address
		if key.rstrip() == 'MAC Address':
			mac_addr=value.lstrip().rstrip()	

		# Find the IP Address
		if key.rstrip() == 'IP Address':
			ip_addr=value.lstrip().rstrip()	

	if not ip_addr and mac_addr:
		raise Exception,"Failed to parse MAC and IP Address information from ipmitool output.\noutput: %s" % (stdout)

	return (mac_addr,ip_addr)

def initiate_pexpect(bmc_ip,bmc_username,password):
	""" Initiate an SSH session to the remove node using pexpect """
	# Initiate connection
	p = pexpect.spawn('ssh %s@%s' % (bmc_username,bmc_ip))
	p.setecho(False)
	p.expect('\'s password:')
	p.send(password + "\n")
	p.expect('\n# $')

	return p

def expect_adjust_cols(p,max_cols):
	""" Adjust the window size so its several chars larger than our biggest command """
	p.setwinsize(p.getwinsize()[0],max_cols)
	if not p.getwinsize()[1] >= max_cols:
		raise Exception,"Couldn't make window wide enough. This will present problems with string matching"

def expect_match_macaddr(p,bmc_mac):
	""" Ensure the MAC address we discovered from the physical node matches the BMC to which we SSH'd """

	get_macaddr_cmd="ifconfig eth0 | egrep 'HWaddr' | awk '{ print $5 }'"

	# Ok...ready to go. Lets make sure the mac addresses match
	p.send(get_macaddr_cmd + "\n")
	p.expect_exact(get_macaddr_cmd + "\r\n")
	this_bmc_mac=p.readline().rstrip().lstrip()
	if not this_bmc_mac.rstrip().upper() == bmc_mac.upper():
		raise Exception,"BMC MAC address (%s) doesn't match specified (%s)" % (this_bmc_mac,bmc_mac)

	p.expect('# ')

def expect_set_hostname(p,bmc_hostname):
	""" Set or update the 'hostname $hostname' field in /conf/interfaces and restart udhcpc """
	# Strip out harmful charachters
	bmc_hostname=re.sub('[^a-zA-Z0-9_.-]','',bmc_hostname)
	interfaces_file='/conf/interfaces'
	define_hostname_cmd= \
		"if egrep '^[[:space:]]{0,}hostname[[:space:]]{0,}.*$' %(interfaces_file)s >/dev/null ;" \
		"then sed -r 's/^[[:space:]]{0,}hostname[[:space:]]{0,}.*$/hostname %(hostname)s/g' -i %(interfaces_file)s ;" \
		"else echo \"hostname %(hostname)s\" >> %(interfaces_file)s ;" \
		"fi" \
		% {'hostname':bmc_hostname,'interfaces_file':interfaces_file}

	expect_adjust_cols(p,len(define_hostname_cmd) + 10)
	# If we got here the mac addresses match. Lets set the hostname
	p.send(define_hostname_cmd + "\n")
	p.expect_exact(define_hostname_cmd + "\r\n")
	p.expect_exact("# ")
	p.send("kill -9 `cat /var/run/udhcpc.eth0.pid`\n")
	p.expect_exact("# ")
	p.send("ifup eth0\n")
	p.expect_exact("# ")

def expect_error_checking(p):
	# This is some error detection stuff that needs some help...
	"""
	# Send a newline so that readline() will work
	#p.send("\n")

	# Lets see if we have a command prompt or not
	unexpected_output=''
	while 1:
		try:
			first_chars=p.read_nonblocking(size=2,timeout=1)
			if first_chars == '# ':
				# Break out of the loop
				break
			else:
				# Gather unexpected output. We assume output is newline-terminated.
				unexpected_output=unexpected_output + first_chars + p.readline()
		except pexpect.TIMEOUT,e:
			print "No data ready...not sure what to do"

	if unexpected_output:
		print unexpected_output.rstrip()
	#"""

if __name__ == "__main__":
	(bmc_mac,bmc_ip)=get_bmc_ip_from_node(node_name)
	p=initiate_pexpect(bmc_ip,bmc_username,bmc_password)
	expect_match_macaddr(p,bmc_mac)
	expect_set_hostname(p,bmc_hostname)
