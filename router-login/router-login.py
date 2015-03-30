#!/usr/bin/python
import paramiko
import getpass
import time
import re
import os
import datetime


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
########################################

print "logging into the device now....."
#Let's grab the running configuration from the router.
time.sleep(1)
chan.send('term len 0\n')
time.sleep(1)
chan.send('sh run\n')
time.sleep(15)
#The following statement will grab the output from the ssh connection.
output = chan.recv(10000000)

print "extracting the interfaces now...."
#We now want to find all interfaces configured on the router.  Be cautious, if you have any NAT, EEM or other random interface
#statements they will be captured in the following regex.  You might need to fine tune the regex code to suite your needs.
s =  re.findall('interface.*',output)
print "Printing the interfaces found:"
for x in s:
	print x


#Reset the output variable so we only print the interface configurations.
output = ""

print "printing out the interface configurations...."
#Print out the running configuration of the interfaces found.
for x in s:
    # stdin,stdout,stderr = chan.send("sh run " + x + "\n")
    chan.send("sh run " + x + "\n")
    time.sleep(1)
    output = output + chan.recv(9999)
    #output = output + chan.recv(10000000)
print output
outputfile = "router-output" + str(time.strftime("%Y-%m-%d-%H:%M:%S"))
#output = chan.recv(10000000)
text_file = open(outputfile, "a")
text_file.write(output)
text_file.close()
chan.send('exit\n')
chan.close()
