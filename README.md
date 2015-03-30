Network Scripts
===================

This is a collection of network scripts that can be used as examples or run on networks. This is a place to store and find scripts that may be useful. Many network operators have small tools or scripts they've built, and by placing them here people can find and expand on each others tools.

Support
----
This is all best effort and under the Apache license unless otherwise noted in the script or script folder.

Scripts:
----
| Script                    |    Description                                                                                                                  |
|---------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| STP-map:                  | A NXAPI script that will create a topology map of the STP instance on a VLAN and open the map in a browser. |
| router-login              | This example script will launch an ssh session to an IP provided by the user, grab a list of interfaces and then print out their configurations.       |
| More to come              | Contact nicmatth@cisco.com to add your script |

More to come on scripts.

To add your script to this repository:
----
Please see details on the NPUG wiki. (The is Link under construction). Email nicmatth@cisco.com in the meantime.

Format:
----
Each script is in it's own folder, with a README, optional license, and the script file(s). A .network file is also preferred.

.network file:
----
In order to quickly ascertain what a script is used for and the context, please include a .network file with the script. This files includes information regarding the device requirements, language, OS support, how secure/tested/complete the code is, and author. A sample would be similar to:
```
{
    description: "Builds a STP topology and displays the details into a webpage",

    language: ["python"],
    operating_systems: ["linux", "windows"],

    author: "Nick Matthews",
    author_email: "nicmatth@cisco.com",

    vendors: ["cisco"],
    products: ["n9000","n7000","n6000","n5000"],
    access_method: ["nxapi"],
    device_protocol: ["STP", "CDP", "VPC", "L2"],

    # Best guess of how much of a 'hack' the script is
    language_bestpractices: .5,
    # What percentage of reasonable features are implemented
    completeness: .8,

    # Best guess of security best practices and methods
    security_level: .8,

    # Best guess of how many failure scenarios have been tested
    test_coverage: .7,

}
````
