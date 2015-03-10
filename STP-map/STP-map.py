__author__ = "nicmatth@cisco.com"

import requests
import json
import sys
from graphviz import Graph
# requires pip install graphviz
import os.path
import os
import datetime
import webbrowser
# for opening files in system web browser
import argparse
import getpass
import re


class Vividict(dict):
    # All dictionary keys will automatically be assigned using the Vividict
    #  more here: http://stackoverflow.com/questions/635483/what-is-the-best-way-to-implement-nested-dictionaries-in-python
    def __missing__(self, key):
        value = self[key] = type(self)()
        return value

# these variables can be set in case they aren't passed via CLI
# these take priority over other methods of input,intended for troubleshooting
# 10.201.30.194","10.201.30.195
override_hosts_string = ["X.X.X.X", "Y.Y.Y.Y"]
override_switchuser = '#USER'
override_switchpassword = '#PASSWORD'
override_vlan_num = 0
verbosity = False
template_file = "template.html"  # assume local directory

# disable annoying security messages - WARNING SSL certs NOT verified
#requests.packages.urllib3.disable_warnings()

# collection variables, collected via CLI argument
log_output = ["Initialized.", ]
myheaders = {'content-type': 'application/json-rpc'}

# output variables for creating html document
# pardon this long string - this is a backup incase the template.html
# isn't loaded, for portability
template_backup = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Subnet graph for VLAN #VLAN</title></head><body><script type="text/vnd.graphviz" id="data">#GRAPH </script><script src="http://mdaines.github.io/viz.js/viz.js"></script><script>      function inspect(s) {        return "<pre>" + s.replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\"/g, "&quot;") + "</pre>"      }            function example(id, format, engine) {        try {          return Viz(document.getElementById(id).innerHTML, format, engine);        } catch(e) {          return inspect(e.toString());        }      }      document.body.innerHTML += "<h1>Spanning-tree for VLAN #VLAN at #TIME</h1>";      document.body.innerHTML += example("data", "svg")</script> <br><br><table><tr><td><b>Legend</b></td></tr><tr><td><hr color="purple" size=3 width=40px></td><td>Status Unknown</td></tr><tr><td><hr color="red" size=3 width=40px></td><td>Disabled or Disconnected</td></tr>  <tr><td><hr color="orange" size=3 width=40px></td><td>Root or Designated Blocking</td></tr> <tr><td><hr color="black" size=3 width=40px></td><td>Blocking</td></tr>  <tr><td><hr color="yellow" size=3 width=40px></td><td>Learning</td></tr>  <tr><td><hr color="blue" size=3 width=40px></td><td>Forwarding</td></tr>  <tr><td><svg height="8" width="40"><line x1="0" y1="3" x2="40" y2="3" style="stroke:rgb(0,0,0);" stroke-width="4" stroke-dasharray="5,2" /></svg> </td><td>VPC (Any color)</td></tr></table><br><h2>Log Data:<br></h2><p>#LOG</p></body></html>'


def command_array(vlan):
    # these are the commands that are requested from each switch once
    # adding new commands requires feeding them into the build topology funcs
    return [
        "show spanning-tree vlan " + str(vlan),
        "show hostname",
        "show cdp neighbor detail",
        "show interface status",
        "show port-channel summary",
        "show vpc brief"
    ]


def add_to_log(log_message):
    if verbosity is True:  # verbose mode, log+print everything
        log_output.append(log_message)
        print log_message
    elif "DEBUG" not in log_message:
        # non verbose mode: log anything above DEBUG, print ERROR only
        log_output.append(log_message)
        if "ERROR" in log_message:
            print log_message
    return 0


def print_log():
    return "<br>".join([w.replace("\n", "<br>").replace('"', "'").replace("\\", "\\\\") for w in log_output])


def return_array(jsondata):
    # this function takes either an array of dictionaries or a single
    #  dictionary, and returns an array of a single dictionary.
    #  Due to the way JSON gets parsed by NXAPI, sometimes the same
    #  element name ex. ROW_interface will have either of these data
    #  types. This makes parsing it, as it will always be an array
    if isinstance(jsondata, dict):
        return [jsondata]
    elif isinstance(jsondata, []):
        if len(jsondata) > 0:
            return jsondata
        else:
            return 1
    else:
        return 1


def parse_arguments():
    parser = argparse.ArgumentParser(description="Builds a STP Topology")
    parser.add_argument('--user', '-u', metavar="user", type=str, nargs='?',
                        help="Default username for login. Also available via "
                        "environment variable STP_USER")
    parser.add_argument('--password', '-p', metavar="password", type=str,
                        nargs='?',
                        help="Default password for login. Also available via "
                        "environment variable STP_PWD")
    parser.add_argument('--device_file', '-f', metavar="device_file", type=str,
                        nargs='?',
                        help="File with device IP addresses each on a new line"
                        ", or they can be set statically set in the script in "
                        "hosts_string")
    parser.add_argument('--vlan', '-v', default=1, metavar="vlan", type=int,
                        nargs=1,
                        help="Specify a VLAN for collecting Spanning Tree"
                        " information (defaults to VLAN 1)")
    parser.add_argument('--verbose', '-V', action="store_true",
                        help="Display the JSON used in building the topology")

    return parser.parse_args()


def parse_device_file(device_file):
    host_list = []
    if os.path.isfile(device_file) == False:  # file doesn't exist
        # write the file from our local variable
        add_to_log("ERROR: File " + device_file + "not found. Exiting")
        quit(1)
    try:
        f = open(device_file, "r")
        lines = f.read()
        # rather than strict formatting, searching for anything that resembles
        # an IP address. Don't put stupid IP addresses in. Sorry IPv6.
        ip_addresses = re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", lines)
        host_list.extend(ip_addresses)
        if len(host_list) == 0:
            add_to_log("ERROR: Read file: " + device_file + " but found no "
                       "IP addresses. Please add addresses 1 per line.")
            quit(1)
        f.close()
        return host_list
    except:
        add_to_log("ERROR: Could not open file " + device_file + ". Bummer")
        quit(1)


def intialize_inputs(arguments):
    # order of preference for username and password:
    #   1. overrideen in the override_switch[user|password] variable above
    #   2. input given via the CLI via the -u and -p variables
    #   3. environment variables STP_USER and STP_PWD
    #   4. manual input via raw_input and getpass
    inputs = {}
    # initialize the username
    if override_switchuser != "#USER":
        inputs["switchuser"] = override_switchuser
        add_to_log("INFO: Overriding the username, suggest env variable "
                   "STP_USER or to input via CLI via -u parameter")
    elif arguments.user is not None:
        inputs["switchuser"] = arguments.user
    else:
        try:
            inputs["switchuser"] = os.environ["STP_USER"]
        except KeyError:
            inputs["switchuser"] = raw_input("User: ")

    # initialize the password
    if override_switchpassword != "#PASSWORD":
        inputs["switchpassword"] = override_switchpassword
        add_to_log("INFO: Overriding the password, suggest env variable "
                   "STP_PWD or to input via CLI via -p parameter")
    elif arguments.password is not None:
        inputs["switchpassword"] = arguments.password
    else:
        try:
            inputs["switchpassword"] = os.environ["STP_PWD"]
        except KeyError:
            inputs["switchpassword"] = getpass.getpass("Password:")

    # intialize the VLAN. Priority for hard coded before CLI
    if override_vlan_num != 0:
        inputs["vlan_num"] = override_vlan_num
        add_to_log("INFO: Overriding the VLAN number, suggest "
                   "using input via CLI -v parameter")
    else:
        inputs["vlan_num"] = arguments.vlan
        if arguments.vlan == 1:
            add_to_log("WARNING: Using default VLAN of 1. Use -v parameter "
                       "or override_vlan_num to specify a different VLAN")

    # initialize the host list
    if override_hosts_string[0] != "X.X.X.X":
        inputs["hosts_string"] = override_hosts_string
    elif arguments.device_file is not None:
        inputs["hosts_string"] = parse_device_file(arguments.device_file)
    else:
        add_to_log("ERROR: No host IP's given. Use the -f parameter or "
                   "statically define in override_hosts_string")
        quit(1)

    return inputs


def create_command_data(command, num):
    return [
        {
            "jsonrpc": "2.0",
            "method": "cli",
            "params": {
                "cmd": command,
                "version": 1
            },
            "id": num
        }
    ]


def build_urls(hosts, secure=True):
    # hosts is an array of IP addresses, returns nxapi url for addresses
    if secure is True:
        return ["https://"+host+"/ins/" for host in hosts]
    else:
        return ["http://"+host+"/ins/" for host in hosts]


def get_response(payload, url, switchuser, switchpassword):
    # attempts to collect the REST data from the selected URL
    # credit to jeff@cisco.com for error handling
    # inputs: the payload is all the show commands in a single array (or entry)
    #         the URL is the IP https/http for the switch, and user/password
    try:
        return requests.post(url, data=json.dumps(payload), timeout=5,
                             headers=myheaders,
                             auth=(switchuser, switchpassword),
                             verify=False).json()
    except requests.exceptions.InvalidURL:
        add_to_log("ERROR: Invalid URL" + url)
        return 1
    except ValueError:
        add_to_log("ERROR: Invalid Username/password combination on " + url)
        return 1
    except requests.exceptions.ConnectionError:
        add_to_log("ERROR: No Connection to " + url + "\nCheck for NXAPI "
                   "support (Nexus 9000 and other Nexus Devices on 7.2+), and "
                   "verify NXAPI feature is enabled:")
        add_to_log("Example:\nSwitch#conf t\nSwitch(config)#feature nxapi\n")
        return 1
    except requests.exceptions.Timeout:
        add_to_log("ERROR: Switch is not reachable on " + url)
        return 1
    except:
        add_to_log("ERROR: tried to retrieve command from " + url + ", failed")
        add_to_log(str(sys.exc_info()[0]))
        return 1


def interface_state(interface_name, interface_status_output):
    int_status_list = return_array(interface_status_output["result"]["body"]["TABLE_interface"]["ROW_interface"])
    for interface in int_status_list:
        if interface_name == interface["interface"]:
            return interface["state"]
    return "Unknown"


def set_interface_state(topology, hostname, list_of_interfaces, interface_status_output):
    # takes a topology data structure, list of interface names, and
    #  the output of 'show interface status' and sets the status of
    #  the interface.
    int_status_list = return_array(interface_status_output["result"]["body"]["TABLE_interface"]["ROW_interface"])
    for ROW_interface in int_status_list:
        # interface listed in show cmd
        interface_name = ROW_interface["interface"]
        if interface_name in list_of_interfaces:
            topology[hostname]["stp_ports"][interface_name]["state"] = ROW_interface["state"]
    return topology


def portchannel_members(portchannel_id, portchannel_output):
    # return an array of any members of a given portchannel
    # output expected to be 'show port-channel summary'
    # int_ids = []
    portchannel_list = return_array(portchannel_output["result"]["body"]["TABLE_channel"]["ROW_channel"])
    # go through the array looking for the portchannel name
    for e in portchannel_list:
        if e["port-channel"] == portchannel_id:
            return [port["port"] for port in return_array(e["TABLE_member"]["ROW_member"])]

    add_to_log("WARNING: Not found: " + portchannel_id)
    return 1


def is_vpc(portchannel_id, vpc_output):
    # given a string of the portchannel id : port-channelXX and the
    #  output of 'show vpc brief' it will check whether it's a vpc
    # the output uses different formatting - PoXX vs port-channelXX
    for entry in return_array(vpc_output["result"]["body"]["TABLE_vpc"]["ROW_vpc"]):
        if entry["vpc-ifindex"] == portchannel_id or entry["vpc-ifindex"] == "Po" + filter(str.isdigit, str(portchannel_id)):
            return True
    return False


def remove_parenthesis_text(host_string):
    if host_string.find('(') > 0:
        return host_string[0:host_string.find('(')]
    return host_string


def get_cdp_adjancency(local_interface, cdp_output):
    # returns the hostname, remote interface, remote + ip for a given local
    #  interface with 'show cdp neighbor' and local interface name
    interface_list = return_array(cdp_output["result"]["body"]["TABLE_cdp_neighbor_detail_info"]["ROW_cdp_neighbor_detail_info"])
    for interface in interface_list:
        if interface["intf_id"] == local_interface:
            # new CDP neighbor information adds serial number to hostname.
            # script currently doesn't use the serial, so just remove it.
            return interface["port_id"], remove_parenthesis_text(interface["device_id"]), interface["v4mgmtaddr"]
    # this means nothing was found, return Unkonwn
    return "Unknown", "Unknown", "Unknown"


def set_adjancency_status(topology, hostname, list_of_interfaces, cdp_output, interface_status_output, portchannel_output, vpc_output):
    # this function checks for members of portchannels and maps  to subports
    # if it's not a portchannel it collects the interface information and adds
    # it as a subport for consistency with portchannel structure
    for interface_name in list_of_interfaces:
        if "port-channel" in interface_name:  # handling for portchannels
            members = portchannel_members(interface_name, portchannel_output)
            # check if it' s a vpc. we'll graph vpc's differently
            isvpc = is_vpc(interface_name, vpc_output)
            for member in members:
                port, host, ip = get_cdp_adjancency(member, cdp_output)
                topology[hostname]["stp_ports"][interface_name]["sub_ports"][member]["adj_port"] = port
                topology[hostname]["stp_ports"][interface_name]["sub_ports"][member]["adj_host"] = host
                topology[hostname]["stp_ports"][interface_name]["sub_ports"][member]["adj_ip"] = ip
                topology[hostname]["stp_ports"][interface_name]["sub_ports"][member]["is_vpc"] = isvpc
                topology[hostname]["stp_ports"][interface_name]["sub_ports"][member]["state"] = interface_state(member, interface_status_output)
        else:  # should be a normal interface E#/#, mgmt0, VlanX, etc
            # putting all port data into 'subport'
            # for consistency with portchannels
            port, host, ip = get_cdp_adjancency(interface_name, cdp_output)
            topology[hostname]["stp_ports"][interface_name]["sub_ports"][interface_name]["adj_port"] = port
            topology[hostname]["stp_ports"][interface_name]["sub_ports"][interface_name]["adj_host"] = host
            topology[hostname]["stp_ports"][interface_name]["sub_ports"][interface_name]["adj_ip"] = ip
            topology[hostname]["stp_ports"][interface_name]["sub_ports"][interface_name]["is_vpc"] = False
            # inherit state from parent version of port
            topology[hostname]["stp_ports"][interface_name]["sub_ports"][interface_name]["state"] = topology[hostname]["stp_ports"][interface_name]["state"]
    return topology


def stp_is_disabled(topology_a, hostname):
    # will return whether STP is disabled, returns 1 if not found
    for topo in topology_a:
        for key in topo.keys():
            if key == hostname:
                return topo[hostname]["stp_active"] == "disabled"
    # not found
    return 1


def get_sub_ports(topology):
    # returns subport names of a given portchannel
    # assumes [topology_a[i][new_hostname]["stp_ports"]
    sub_ports = []
    for value in topology.values():
        for subport, subvalue in value["sub_ports"].items():
            if isinstance(subvalue, Vividict):
                sub_ports.append(subport)
    return sub_ports


def add_adj_nodes(topology_a):
    # this function creates new topology and new dict entry for nodes
    # in the adjacency table without an entry from a topology array
    node_names = [topo.keys()[0] for topo in topology_a]
    new_nodes = Vividict()
    for topo in topology_a:
        for hostname, pdict in topo.items():
            for portname, port_dict in pdict["stp_ports"].items():
                # if it's the port identifier with sub dictionary
                if isinstance(port_dict, Vividict):
                    for subportname, subport_dict in port_dict["sub_ports"].items():
                        new_hostname = subport_dict["adj_host"]
                        new_subport = subport_dict["adj_port"]
                        if new_subport == "STP_NA":
                            break  # leave the STP NA filler information alone
                        if isinstance(subport_dict, Vividict):  # if it's the sub_ports dict
                            # this is looping in every subport of every port of every host in the array
                            if new_hostname not in node_names:  # a host we don't know about
                                add_to_log("INFO: Adding new found node " + new_hostname + "port" + new_subport + "to array")
                                new_nodes[new_hostname]["ip_address"] = subport_dict["adj_ip"]
                                new_nodes[new_hostname]["is_root"] = "Unknown"
                                new_nodes[new_hostname]["priority"] = "Unknown"
                                new_nodes[new_hostname]["stp_active"] = "Unknown"
                                # if we're getting CDP information, assume the port is up
                                new_nodes[new_hostname]["stp_ports"][portname]["state"] = "connected"
                                new_nodes[new_hostname]["stp_ports"][portname]["stp_role"] = "Unknown"
                                new_nodes[new_hostname]["stp_ports"][portname]["stp_state"] = "Unknown"
                                new_nodes[new_hostname]["stp_ports"][portname]["sub_ports"][new_subport]["state"] = "connected"
                                new_nodes[new_hostname]["stp_ports"][portname]["sub_ports"][new_subport]["adj_port"] = subportname
                                new_nodes[new_hostname]["stp_ports"][portname]["sub_ports"][new_subport]["adj_host"] = hostname
                                new_nodes[new_hostname]["stp_ports"][portname]["sub_ports"][new_subport]["is_vpc"] = "Unknown"
                                new_nodes[new_hostname]["stp_ports"][portname]["sub_ports"][new_subport]["adj_ip"] = pdict["ip_address"]
                            else:
                                # it's a known host
                                for i, node_name in enumerate(node_names):
                                    if node_name == new_hostname:
                                        known_ports = topology_a[i][new_hostname]["stp_ports"].keys()
                                        known_subports = get_sub_ports(topology_a[i][new_hostname]["stp_ports"])
                                        if new_subport not in known_ports and new_subport not in known_subports:
                                            # it's a new port
                                            topology_a[i][new_hostname]["stp_ports"][new_subport]["state"] = "connected"
                                            topology_a[i][new_hostname]["stp_ports"][new_subport]["stp_role"] = "Unknown"
                                            topology_a[i][new_hostname]["stp_ports"][new_subport]["stp_state"] = "Unknown"
                                            topology_a[i][new_hostname]["stp_ports"][new_subport]["sub_ports"][new_subport]["state"] = "connected"
                                            topology_a[i][new_hostname]["stp_ports"][new_subport]["sub_ports"][new_subport]["adj_port"] = subportname
                                            topology_a[i][new_hostname]["stp_ports"][new_subport]["sub_ports"][new_subport]["adj_host"] = hostname
                                            topology_a[i][new_hostname]["stp_ports"][new_subport]["sub_ports"][new_subport]["is_vpc"] = "Unknown"
                                            topology_a[i][new_hostname]["stp_ports"][new_subport]["sub_ports"][new_subport]["adj_ip"] = pdict["ip_address"]

    # add all the new nodes to the existing topology array
    topology_a.extend([Vividict({k: v}) for k, v in new_nodes.items()])
    # to check the different between the two sets of nodes
    # print json.dumps(topology_a,indent=2)
    # print json.dumps(new_nodes,indent=2)
    return topology_a


def buildtopology(stp_output, hostname_output, cdp_output, interface_status_output, portchannel_output, vpc_output, host_ip):
    # this function does the hard work of taking the output of the commands
    # and putting it into a nested dictionary for the topology of one host
    topology = Vividict()

    # gather some basic initial variables
    hostname = hostname_output["result"]["body"]["hostname"]
    # shortcut for accessing STP json
    try:
        ROW_tree = stp_output["result"]["body"]["TABLE_tree"]["ROW_tree"]
        ROW_port = ROW_tree["TABLE_port"]["ROW_port"]
    except TypeError:
        # STP is disabled on this VLAN, TypeError on null input for ROW_tree
        add_to_log("ERROR: STP Disabled on " + hostname)
        topology[hostname]["stp_active"] = "disabled"
        topology[hostname]["ip_address"] = host_ip
        topology[hostname]["root"] = False
        topology[hostname]["priority"] = "NA"
        topology[hostname]["stp_ports"]["STP_NA"]["state"] = "STP_NA"
        topology[hostname]["stp_ports"]["STP_NA"]["stp_role"] = "STP_NA"
        topology[hostname]["stp_ports"]["STP_NA"]["stp_state"] = "STP_NA"
        topology[hostname]["stp_ports"]["STP_NA"]["sub_ports"]["STP_NA"]["state"] = "STP_NA"
        topology[hostname]["stp_ports"]["STP_NA"]["sub_ports"]["STP_NA"]["adj_port"] = "STP_NA"
        topology[hostname]["stp_ports"]["STP_NA"]["sub_ports"]["STP_NA"]["adj_host"] = "STP_NA"
        topology[hostname]["stp_ports"]["STP_NA"]["sub_ports"]["STP_NA"]["is_vpc"] = "STP_NA"
        topology[hostname]["stp_ports"]["STP_NA"]["sub_ports"]["STP_NA"]["adj_ip"] = "STP_NA"
        return topology

    if_index = []
    state = []
    role = []

    # check STP output
    # check for root
    isroot = False
    if ROW_tree["tree_designated_root"] == ROW_tree["bridge_mac"]:
        isroot = True

    # set variables for root and priority. all dictionary keys will
    # automatically be assigned using the Vividict
    # more here: http://stackoverflow.com/questions/635483/what-is-the-best-way-to-implement-nested-dictionaries-in-python
    topology[hostname]["root"] = isroot
    topology[hostname]["ip_address"] = host_ip
    topology[hostname]["priority"] = ROW_tree["bridge_priority"]
    topology[hostname]["stp_active"] = ROW_tree["stp_active"]

    # convert array of ports, states, and roles into lists
    # if there's only 1 port it's a dict, so convert to single entry array
    array_ROW_port = return_array(ROW_port)
    if array_ROW_port != 1:
        for x in array_ROW_port:
            if_index.append(x["if_index"])  # this could include portchannels
            state.append(x["state"])
            role.append(x["role"])
    else:
        add_to_log("ERROR: The STP state is neither a dict or array, or empty")

    # map the stp_id for the hostname to the role/state of interface
    for interface_name, st, ro in zip(if_index, state, role):
        topology[hostname]["stp_ports"][interface_name]["stp_state"] = st
        topology[hostname]["stp_ports"][interface_name]["stp_role"] = ro

    # assign status to stp port (portchannel or physical/mgmt interface)
    topology = set_interface_state(topology, hostname,
                                   if_index, interface_status_output)
    # find subports for port channels and assign state and adjacency infomation
    topology = set_adjancency_status(topology, hostname, if_index, cdp_output,
                                     interface_status_output,
                                     portchannel_output, vpc_output)
    # build a link graph structure from the topology

    return topology


def create_topology(arg_inputs):
    # this function is the master function for building the json data for the
    # topology. it sets the topology as array of dictionaries with unique keys
    # that can be combined into a single dictionary with unique keys if needed

    # intermediary variables
    payload = []
    topo_array = []
    # build http URLs for our hosts.
    urls = build_urls(arg_inputs["hosts_string"])
    # build a REST request for each command in the command array
    for i, x in enumerate(command_array(arg_inputs["vlan_num"])):
        payload.extend(create_command_data(x, i))
    # assign variables for each of the outputs of the show commands
    # then loop through our hosts and commands and feed that into the
    # topology builder
    if len(arg_inputs["hosts_string"]) == 0:
        add_to_log("ERROR: No devices provided")
    for host, url in zip(arg_inputs["hosts_string"], urls):
        response_data = get_response(payload, url, arg_inputs["switchuser"], arg_inputs["switchpassword"])
        if response_data == 1:
            # there was an error in getting commands, break
            add_to_log("ERROR: Collecting show commands failed")
            continue
        else:
            stp_o, hostname_o, cdp_o, intstatus_o, portchannel_o, vpc_o = response_data
        new_topo = (buildtopology(stp_o, hostname_o, cdp_o, intstatus_o,
                                  portchannel_o, vpc_o, host))
        # check for duplicate hostnames across the array
        for thekey in new_topo:  # in case of empty array
            if thekey == []:
                continue
            for topo in topo_array:
                if thekey in topo:
                    # add a (dup) if the key already exists
                    add_to_log("ERROR: Duplicate host names found, "
                               "results perilous")
                    new_topo[thekey + "(dup)"] = new_topo.pop(thekey)
        topo_array.append(new_topo)

    # clean up data once we've gone through all input and data collection
    topo_array = add_adj_nodes(topo_array)

    return topo_array


def find_subport(topology_a, hostname, subport):
    # returns the dictionary for a port, plus the STP role+state of the parent
    x = -1
    for i, topo in enumerate(topology_a):
        if hostname in topo.keys():
            x = i
    if x == -1:
        add_to_log("ERROR: Looking for hostname " + hostname +
                   ", not found in array")
        return -1
    if subport in topology_a[x][hostname]["stp_ports"].keys():
        # it's a physical interface,the subport will match the parent port
        sdict = topology_a[x][hostname]["stp_ports"][subport]["sub_ports"][subport]
        sdict["stp_role"] = topology_a[x][hostname]["stp_ports"][subport]["stp_role"]
        sdict["stp_state"] = topology_a[x][hostname]["stp_ports"][subport]["stp_state"]
        return sdict

    # let's see if it's in a port channel, search the subports
    for ports, ports_dict in topology_a[x][hostname]["stp_ports"].items():
        for possible_sub_port, psub_dict in ports_dict["sub_ports"].items():
            if possible_sub_port == subport:
                psub_dict["stp_role"] = ports_dict["stp_role"]
                psub_dict["stp_state"] = ports_dict["stp_state"]
                return psub_dict

    add_to_log("ERROR: Could not find subport " + subport +
               " for hostname " + hostname + " in array")
    return -1


def build_links(topology_a):
    # the topology file isn't ideal for identifying links between hosts,
    # this is explicit though redundant
    links = []
    already_added = []
    for topo in topology_a:  # individual topology data in array
        for switch, switch_dict in topo.items():
            for parent_port, port_dict in switch_dict["stp_ports"].items():
                for subport1, subport1_dict in port_dict["sub_ports"].items():
                    node1 = switch
                    node2 = subport1_dict["adj_host"]
                    subport2 = subport1_dict["adj_port"]
                    subport2_dict = find_subport(topology_a, node2, subport2)
                    # we have to transfer the stp state/role to
                    # the subport graph for per-link color.
                    # the find_subport already inserted the role and state so
                    # that the graph can use it per subport
                    subport1_dict["stp_role"] = port_dict["stp_role"]
                    subport1_dict["stp_state"] = port_dict["stp_state"]
                    if node1 > node2:  # alphabetize so node 1 is lower, otherwise remain same
                        node1,subport1,subport1_dict,node2,subport2,subport2_dict = node2,subport2,subport2_dict,node1,subport1,subport1_dict

                    if (node1, subport1, node2, subport2) not in already_added:
                        links.append({
                            "node1": node1,
                            "node2": node2,
                            "int1": subport1,
                            "int2": subport2,
                            "int1_dict": subport1_dict,
                            "int2_dict": subport2_dict
                            })
                        already_added.append((node1, subport1, node2, subport2))
    return links


def friendly_name(int_name):
    # the graphviz parser doesn't like certain characters, so we replace them
    replace_tuple = [('/', 'slash'), ('\\', 'fslash'), (".", "dot"),
                     ('<', 'lcaret'), ('>', 'rcaret'), ('"', "dquote"),
                     ("'", "squote"), ("port-channel", "po"),
                     ("Ethernet", "eth")]

    for k, v in replace_tuple:
        int_name = int_name.replace(k, v)
    return int_name


def build_graph_label(topology_json):
    # this builds the array string that builds the record type graphviz
    array_str = ""
    head = "{ "
    tail = " }"
    separator = " | "
    array_str += head
    for switch, v in sorted(topology_json.items()):
        array_str += switch
        array_str += "\\nPriority: " + str(v["priority"])
        if v["root"] == True:
            array_str += " (Root)"
        array_str += "\\nIP: " + str(v["ip_address"])
        for port_name, port_dict in sorted(v["stp_ports"].items()):
            if "port-channel" in port_name:
                array_str += separator + head + "<" + \
                    friendly_name(port_name) + "> "
                # check if it's a vpc
                isvpc = ""  # if it's false we won't insert anything
                for v in port_dict["sub_ports"].values():
                    if v["is_vpc"] == True:
                        isvpc = "(VPC)"
                    break
                array_str += port_name + isvpc + separator + head
                for subport_name, subport_dict in sorted(port_dict["sub_ports"].items()):
                    isdown = ""  # will be empty if port is connected
                    array_str += "<" + friendly_name(subport_name) + ">"
                    if subport_dict["state"] != "connected":
                        isdown = "(" + subport_dict["state"] + ")"
                    array_str += subport_name + isdown + separator
                # remove the last separator
                array_str = array_str[0:-len(separator)]
                # terminate the first two heads
                array_str += tail + tail
            else:
                if isinstance(port_dict, Vividict):
                    array_str += separator
                    array_str += "<" + friendly_name(port_name) + ">"
                    array_str += port_name
    array_str += tail
    return array_str


def set_link_color(port_dictionary):
    # figure out the link color for each half, most critical first
    state = port_dictionary["stp_state"].lower()
    role = port_dictionary["stp_role"].lower()
    if state == "unknown" or state == "stp_na":
        return "purple"
    if state == "disabled" or port_dictionary["state"] != "connected":
        return "red"
    if state == "blocking" and (role == "designated" or role == "root"):
        return "orange"
    if state == "blocking":
        return "black"
    if state == "learning":
        return "yellow"
    if state == "forwarding":
        return "blue"


def set_link_defaults():
    return {
            "adj_host": "Unknown",
            "adj_port": "Unknown",
            "adj_ip": "Unknown",
            "state": "Unknown",
            "is_vpc": "Unknown",
            "stp_state": "Unknown",
            "stp_role": "Unknown"
    }


def set_link_attributes(link_dictionary):
    # set attributes for color (per side), label, line style, tooltip
    attributes = {}
    # default line width is 2, 4 for vpc
    attributes["penwidth"] = 2

    if link_dictionary["int1_dict"] == -1:
        link_dictionary["int1_dict"] = set_link_defaults()
    if link_dictionary["int2_dict"] == -1:
        link_dictionary["int2_dict"] = set_link_defaults()

    if link_dictionary["int1_dict"]["is_vpc"] == True or \
       link_dictionary["int2_dict"]["is_vpc"] == True:
        attributes["style"] = "dashed"
        attributes["penwidth"] = 4

    firsthalfcolor = set_link_color(link_dictionary["int1_dict"])
    secondhalfcolor = set_link_color(link_dictionary["int2_dict"])
    if firsthalfcolor == secondhalfcolor:
        attributes["color"] = firsthalfcolor
    else:
        attributes["color"] = firsthalfcolor + ";.5:" + secondhalfcolor
    attributes["tooltip"] = link_dictionary["node1"] + " " + \
        link_dictionary["int1"] + " -> " + link_dictionary["node2"] + \
        " " + link_dictionary["int2"]
    attributes["label"] = link_dictionary["int1"] + ": " + \
        link_dictionary["int1_dict"]["stp_role"] + "/" + \
        link_dictionary["int1_dict"]["stp_state"] + "\n" + \
        link_dictionary["int2"] + ": " + \
        link_dictionary["int2_dict"]["stp_role"] + "/" + \
        link_dictionary["int2_dict"]["stp_state"]

    return attributes


def create_links(link_a):
    link_str = ""
    for i, link_dict in enumerate(link_a):
        host1 = link_dict["node1"]
        host2 = link_dict["node2"]
        int1 = link_dict["int1"]
        int2 = link_dict["int2"]
        link_str += '"' + host1 + '":'
        link_str += friendly_name(int1) + " -- "
        link_str += '"' + host2 + '":'
        link_str += friendly_name(int2)

        attributes = set_link_attributes(link_dict)
        attributes["id"] = str(i)
        link_str += "[ "
        for k, v in attributes.items():
            link_str += k + ' ="' + str(v) + '", '
        link_str = link_str[:-2] + "];\n"  # taking off trailing space+comma
    return link_str


def create_graph(topology_array, link_a):
    dot = Graph(node_attr={'shape': 'record'})

    for topo in topology_array:
        hostname = topo.keys()[0]
        if topo[hostname]["root"] == True:
            dot.node(hostname, build_graph_label(topo),
                     URL="ssh://" + str(topo[hostname]["ip_address"]),
                     style="filled", fillcolor="lightgreen")
        elif topo[hostname]["stp_active"] != "enabled":
            dot.node(hostname, build_graph_label(topo),
                     URL="ssh://" + str(topo[hostname]["ip_address"]),
                     xlabel="STP Disabled", style="filled",
                     fillcolor="darkgray")
        else:
            dot.node(hostname, build_graph_label(topo),
                     URL="ssh://" + str(topo[hostname]["ip_address"]))

    # dot.source are the nodes, and ends with a }, so we limit that
    # using create links we're able to put together the links and attributes
    # in the graphviz format, which are unsupported by the Graph library
    graphtext = dot.source[:-1] + create_links(link_a) + "}"

    return graphtext


def build_html_file(graphdata, local_time, vlan):
    if os.path.isfile(template_file) == False:  # file doesn't exist
        # write the file from our local variable
        add_to_log("ERROR: Attempting to write backup file, "
                   "template not found in directory")
        try:
            o = open(template_file, "w")
            o.write(template_backup)
            # required since file is opened immediately in the next step
            o.flush()
            o.close()
        except:
            add_to_log("ERROR: Writing our template from a local "
                       "variable failed. Bummer")
    try:
        # file already exists, open it up
        template = open(template_file, "r")
        template_data = template.read()
        template.close()
    except:
        add_to_log("ERROR: Could not access " + template_file + ", exiting.")
        return 1

    # exchange our #VAR's for variables
    new_data = template_data.replace("#GRAPH", graphdata).replace("#VLAN", str(vlan)).replace("#TIME", local_time).replace("#LOG", print_log())
    # build filename based on vlan and time for uniqueness
    output_filename = "STP_V" + str(vlan) + "_" + str(local_time) + ".html"
    try:
        # write out the file
        new_file = open(output_filename, "w")
        new_file.write(new_data)
        new_file.close()
        return output_filename
    except:
        add_to_log("ERROR: Could not write our output to " + output_filename)
    return 1


def open_browser(page_url):
    # all of the os, savout, open/close is to prevent firefox stdout to stream
    # to the screen.
    savout = os.dup(1)
    os.close(1)
    os.open(os.devnull, os.O_RDWR)
    try:
        webbrowser.open_new_tab(page_url)
    finally:
        os.dup2(savout, 1)

def main():
    # take the argv arguments
    args = parse_arguments()

    inputs = intialize_inputs(args)
    # any function that calls add_to_log() would need to be passed the
    # verbose argument, so making it a global variable
    global verbosity
    verbosity = args.verbose
    # for debug purposes, print out the inputs we're using
    for k1, v in inputs.items():
        if k1 == "switchpassword":
            add_to_log("DEBUG: " + "(password excluded)")
            # uncomment to debug the password, warning it gets sent to file
            # add_to_log("DEBUG: " + str(v))
        else:
            add_to_log("DEBUG: " + k1 + " " + str(v))

    # create_topology calls build_topology per IP,
    # which calls set_interface_state and status per interface
    # this will build an array of 'topologies'
    full_topology = create_topology(inputs)
    # to print the topology JSON:
    for array_entry in full_topology:
        add_to_log("DEBUG Topology: " + json.dumps(array_entry, indent=2))

    link_graph = build_links(full_topology)
    # to print the link graph
    for array_entry in link_graph:
        add_to_log("DEBUG: Links: " + json.dumps(array_entry, indent=2))

    topology_graph = create_graph(full_topology, link_graph)
    # to print the graphviz data:
    # add_to_log("DEBUG: " + str(topology_graph))
    time_str = datetime.datetime.now().strftime("%m-%d-%Y{%H.%M.%S}")
    filename = build_html_file(topology_graph, time_str, inputs["vlan_num"])

    if filename != 1:  # build_html ran successfully
        open_browser(filename)

if __name__ == '__main__':
    main()
