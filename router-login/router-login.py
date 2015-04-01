#!/usr/bin/python
import paramiko
import getpass
import time
import re
import os


#including this snippet will automatically accept the host keys on ssh requests.
class AllowAllKeys(paramiko.MissingHostKeyPolicy):
    def missing_host_key(self, client, hostname, key):
        return

#input from the user for login credentials and the router/switch ip.
username = raw_input("Please enter the username to run this script: ")
password = getpass.getpass('Password:')
ip_addr = raw_input("Please enter the router IP: ") 

########################################
#This block instantiates the ssh session.
client = paramiko.SSHClient()
client.load_system_host_keys()
client.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
client.set_missing_host_key_policy(AllowAllKeys())
client.connect(ip_addr, username=username, password=password, timeout=7,allow_agent=False,look_for_keys=False)
chan = client.invoke_shell()
chan.settimeout(None)
########################################

print "logging into the device now....."
#Let's grab the running configuration from the router.
time.sleep(1)
chan.send('term len 0\n')
time.sleep(1)
chan.send('sh run\n')
time.sleep(30)
#The following statement will grab the output from the ssh connection.
if chan.recv_ready():
    output = chan.recv(1250000)

print "extracting the interfaces now...."
#We now want to find all interfaces configured on the router.  You might need to fine tune the regex code to suite your needs.
#The following regex statement will grab only the interface statements and will leave out the other parameters
#beyond the port numbers.
s =  re.findall('interface.*[A-Za-z]*/*.[0-9$]',output)

#remove any duplicates found from sub configurations....config the list to a set then back to a list
s = list(set(s))
print "Printing the interfaces found:"
for x in s:
	print x


#Reset the output variable so we only print the interface configurations.
output = ""

print "printing out the interface configurations...."
#Print out the running configuration of the interfaces found.
for x in s:
    chan.send("sh run " + x + "\n")
    time.sleep(1)
    
output = chan.recv(1250000)
print output

chan.send('exit\n')
chan.close()
