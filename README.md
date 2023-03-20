# Network-Validation
### CSE Diploma Thesis. <br>
My diploma thesis for the [Department of Computer Science and Engineering, University of Ioannina](https://www.cse.uoi.gr/) 
- Title: Automatic configuration and validation of network parameters in computer networks. 

## Abstract
The increasing use of electronic devices that have access to the internet and the continuous app and service development on them, are constantly creating larger and more complex networks which all together are part of the greater Internet. This constant escalation and dependence of everyday life on the internet, requires from networks high quality of service, reliability, and security. But as long networks become bigger and bigger, they get more complex their management becomes harder, and the possibility of an error that can arise from human or non-human factors are increasing. To tackle this problem, automation and validation techniques have been developed. <br> <br>
The aim of this work is to present the field of network automation and to deepen in the field of network validation or network testing. We will start by seeing the importance of networks today and the need it creates for the existence of reliable networks, next, we will present what network automation and network validation are and what its processes are, then we will present tools used today in networking by network admins and engineers and finally, we will present our tool, developed for network validation.


## Network Validation Tool
Purpose of this tool is to perform basic validation operations on a computer network and detect any error or misconfiguartion that could break it down. The major steps we follow to set up a network topology and start the validation:<br>
- Network topology initialization
- Device configuration
- Network topology visualization
- Validation of the network topology and its parameters.

### -Network Topology Initialization
For the Network topology Trivial Graph Format is used. TGF is a simple text-based adjecency list file format for descibing graphs. For the purpose of our project we expanded the format to support more complex attributes in its nodes and edges.
### -Device configuration
For each device defined inside the network topology file, there is a configuration file containing the devices network interfaces. The configuration files follow the netplan network configuration format.
### -Network Topology Visualization
For the topology visualization, the pyvis libary is used. It takes as input a NetworkX Graph and tranlates it into a pyvis graph and handles the visualization.The result is a HTML file containing the visualized network topology
### -Network Topology Validation
For the validation of the network, various validation operation are performed upon the network and its devices. The target of those operation is to validate that each device is correctly configurated and works correctly as a unit and that the network as whole (end-to-end) behaves as expected.


## Tools
The project was developed using Python 3.8. These modules-libraries were used to develop it:
- [NetworkX](https://networkx.org/) For the network representation.
- [Pandas](https://pandas.pydata.org/)  For the netwroks data processing.
- [pyvis](https://pyvis.readthedocs.io/en/latest/) For the network visualization.
- [Networking config version 2 from netplan](https://netplan.io/) For device configuration.
## More
For the detailed presentation of the Diploma Thesis and the network validation tool, view the pdf file located at docs.
