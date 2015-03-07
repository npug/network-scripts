#STP-Map

#Description
STP-Map maps out the spanning tree topology of a network and displays the map into a webpage.  This quick view allows for faster troubleshooting and understanding of the network topology, saving time. It will display root information, port status, port channel, virtual port channel, cdp neighbor details, and spanning tree role and state.

#Inputs
The scripts takes in a number of inputs
* File where the IP addresses are defined
* Username
* Password
* VLAN to map
* Verbose option

Details on input:

| Input     |     Description                                                                                                                                                    |
|-----------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| -f        | The file where the IP addresses are entered. IP addresses are to be entered one per line in the file. This option is optional and can be overriden with the override_hosts_string variable, though not recommended. |
| -u        | The username for login. This can also be set via the STP_USER environment variable (recommended) or in the script via the override_switchuser variable. If not entered, the script will query for input. |
| -p        | The password for login. This can also be set via the STP_PWD environment variable (recommeded) or in the script via the override_switchpassword variable. If not entered, the script will query for input. |
| -v        | VLAN number to map. If not entered, it will default to 1. |
| -V        | Verbose option. If used, raw JSON and all errors will be printed the final html output as well as via stdout. |

#Installation
This script requires the requests and graphviz modules, all others should be included. This script is compatible with Python 2.7.
```
git clone http://github.com/npug/network-scripts
pip install graphviz
pip install requests

echo "192.168.1.1" > device-file.txt
python network-scripts/STP-map/STP-map.py -f <device file> -v <VLAN> -u <USERNAME> -p <PASSWORD>
````

#Compatibility
The script uses NX-API to communicate with the switches. This is supported on the Nexus 9300 and 9500 code, and other Nexus code with NX-API support (NX-OS 7.2+). It has been tested on Ubuntu and Windows

#Output
The output of the script should look something like this.
<image to be created>