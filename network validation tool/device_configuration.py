""" Device configuration

    This file is responsible for the device configuration.
    The followed steps to achive this are: 
        
        -Parsing the unconfigurated TGF file containing
        the network topology
        
        -Validating that for each defined device in the TGF file
        a device configuration file exists

        -Parsing the device congifuration files.

        -Validating the device configuration files and values 
        using the config_validation module

        -Using the parsed configuration files, configurating
        the network devices

        -Exporting the configurated TGF file   

"""

import os
import re
import yaml
import copy
from netaddr import *
import config_validation as cv
import tgf_parser as tgf
from tgf_validation import is_unique_edge


# Constants
TOPOLOGIES_DIRECTORY = 'topologies' # The directory were every example is stored
TAB = "    "


# Global variables

# Structures for parsed data
nodes = {}
edges = {}
interfaces = dict()         #All the interfaces parsed from configuration files
node_interfaces = {}    #Every nodes interfaces defined in network topology tgf file

#Routing table
routing_table = {"dest" : [], "mask" : [], "next_hop" : []}
routing_table_list = {}

# Template for different types of network interfaces - create a deepcopy of the template for each new interface 
interface = {'if_id' : ''}
switch_interface = {'if_id' : '', 'mac' : ''}
pc_interface = {'if_id' : '', 'mac' : '', 'ip' : '', 'mask' : '', 'gateway' : '', 'dns' : ''}
router_interface = {'if_id' : '', 'mac' : '', 'ip' : '', 'mask' : '', 'gateway' : '', 'dns' : '', 'nat' : '', 'public_ip': ''}

# Map between node type etc 'Client_PC' and its interface
node_type_interfaces = {'Hub' : interface, 'Switch' : switch_interface, 'Router' : router_interface, 'Client_PC' : pc_interface, 'Server_PC' : pc_interface }



def print_error_msg(filename: str, error_msg: str) -> None:
    """ Prints error message and exits, terminating device configutation"""
    
    print(f"Device configuration Error at file: '{filename}':\n{TAB}-{error_msg}")
    exit()


def find_path(topology: str, filename: str) -> str:
    """ Returns examples full directory path """
    
    # The main directory where the tool - scripts are stored
    current_directory_path = os.path.dirname(os.path.realpath(__file__))

    # Checks that topologies directory exists
    if TOPOLOGIES_DIRECTORY not in os.listdir(current_directory_path):
        print(f"Directory error: {TOPOLOGIES_DIRECTORY} directory was not found at {current_directory_path}")
        exit()

    # The directory path where examples are stored
    topologies_path = current_directory_path + "\\" + TOPOLOGIES_DIRECTORY

    # Checks that examples directory exists
    if topology not in os.listdir(topologies_path):
        print(f"Directory error: {topology} directory was not found at {topologies_path}")
        exit()
    
    examples_path = topologies_path + "\\" + topology

    # Checks that network topology defition exists
    if filename not in os.listdir(examples_path):
        print(f"File Error: Examples {topology} network topology definition {filename} does not exist at: {examples_path}")
        exit()
    
    return examples_path 


def parse_net_topology(path: str, filename: str) -> None:
    """ Parses the unconfigurated network topology 'tgf_parser'"""
    
    global nodes
    global edges
    
    parser = tgf.Def_TGF_Parser(path, filename)
    nodes, edges = parser.parse_network_topology()
    group_nodes_interfaces()


def nodes_config_exists(path: str) -> None:
    """ Checks that there is a unique configuration file for each node-device"""

    # List containing every configuration file 
    config_files_list = [file for file in os.listdir(path) if file.split(".")[1] == 'yml']
    
    def is_valid_naming_pattern() -> None:
        """ Checks that every configuration file matches the naming pattern"""
        
        # Naming pattern for configuration files
        config_file_name_pattern = "^(pc|sr|r|sw|h)\d{1,2}_config.yml"
        
        # Check that every yml file follows the naming pattern
        for file in config_files_list:
            if not bool(re.match(config_file_name_pattern, file)):
                error_msg = f"Configuration file naming error: '{file}' in not a valid configuration file name!"
                print_error_msg(file, error_msg)


    def node_has_config() -> None:
        """ Checks that a configuration file exists for each node"""
        
        # Set with all the nodes that have a configuration file
        config_files_set = set([file.split("_")[0] for file in config_files_list])
        missing_config_nodes = set(nodes) - config_files_set
        if missing_config_nodes:
            error_msg = f"Configuration file missing: Did not find any configuration file for this nodes: {missing_config_nodes}"
            print(error_msg)
            exit()

    is_valid_naming_pattern()
    node_has_config()


def group_nodes_interfaces() -> None:
    """ Groups together the interfaces of every node, found on the tgf file"""
   
    for node in nodes:
        node_interfaces[node] = []
        interfaces[node] = dict()   
    for edge in edges:
        for index, end_node in enumerate(["left_end", "right_end"]):
            if edges[edge][end_node]["if_id"] not in node_interfaces[edge.split(" ")[index]]:
                node_interfaces[edge.split(" ")[index]].append(edges[edge][end_node]["if_id"])


def parse_config_files(path: str) -> None:
    """ Parses the configuration files for the network topology devices"""
    
    for filename in os.listdir(path):
        
        if filename.split(".")[1] == "yml":
            with open(path + "\\" + filename, "r") as stream:
                try:
                    config_data = yaml.load(stream, Loader = yaml.FullLoader)
                    node_id = filename.split("_")[0]
                except yaml.YAMLError as exc:
                    print(exc)
            
            node_type = nodes[node_id]['node_type']
            
            # Validate the configuration file format and values
            cv.start_config_validation(filename, config_data, node_type)
            extract_data_from_config(filename, node_id, config_data)


def check_unconfig_interfaces(filename: str, node_id: str, nodes_interfaces_list: list) -> None:
    """ Checks for any defined interface in the tgf that has not been configured"""
    
    missing_interfaces = set(node_interfaces[node_id]) - set(nodes_interfaces_list)
    if missing_interfaces:
        error_msg = f"Initialaization error: No device initialization for interface: {missing_interfaces}, at node: '{node_id}', was found"
        print_error_msg(filename, error_msg)


def extract_data_from_config(filename: str, node_id: str, config_data: dict) -> None:
    """ Extracts the needed data from the configuration file for every interface defined 
        in it, that later will initialize the devices defined in the tgf file
    """
    
    node_type = nodes[node_id]['node_type']
    nodes_interfaces_list = []
    
    def init_interface(if_id: str):
        """ Initialize an interface from the template for every interface
            in the configuration file
        """     

        my_interface = copy.deepcopy(node_type_interfaces[node_type])
        interfaces[node_id][if_id] = my_interface
        nodes_interfaces_list.append(interface)
        my_interface['if_id'] = interface
        return my_interface
        
    
    if node_type == 'Hub':
        pass

    elif node_type == 'Switch':
        for interface in config_data['network']['ethernets']:
            iface = init_interface(interface)
            iface['mac'] = config_data['network']['ethernets'][interface]['macaddress']

    elif node_type in {'Client_PC', 'Server_PC'}:
        for interface in config_data['network']['ethernets']:
            iface = init_interface(interface)
            iface['mac'] = config_data['network']['ethernets'][interface]['macaddress']
            iface['ip'] = config_data['network']['ethernets'][interface]['addresses'].split('/')[0]
            mask = config_data['network']['ethernets'][interface]['addresses'].split('/')[1]
            iface['mask'] = str(IPNetwork(f'0.0.0.0/{mask}').netmask)
            iface['gateway'] = config_data['network']['ethernets'][interface]['gateway4']
            iface['dns'] = config_data['network']['ethernets'][interface]['nameservers']['addresses'][0]

    elif node_type == "Router":
        for interface in config_data['network']['ethernets']:
            
            # The interface that the routing table is stored. This is a temp solution
            if interface == 'rt':
                my_routing_table = copy.deepcopy(routing_table)
                my_routing_table['dest'] = [str(IPNetwork(addr).ip) for addr in config_data['network']['ethernets'][interface]['routes']['to']]
                my_routing_table['mask'] = [str(IPNetwork(addr).netmask) for addr in config_data['network']['ethernets'][interface]['routes']['to']]
                my_routing_table['next_hop'] = config_data['network']['ethernets'][interface]['routes']['via']
                routing_table_list[node_id] = my_routing_table
            else:
                iface = init_interface(interface)
                iface['mac'] = config_data['network']['ethernets'][interface]['macaddress']
                iface['ip'] = config_data['network']['ethernets'][interface]['addresses'].split('/')[0]
                mask = config_data['network']['ethernets'][interface]['addresses'].split('/')[1]
                iface['mask'] = str(IPNetwork(f"0.0.0.0/{mask}").netmask)
                iface['gateway'] = config_data['network']['ethernets'][interface]['gateway4']
                iface['dns'] = config_data['network']['ethernets'][interface]['nameservers']['addresses'][0]
                iface['nat'] = config_data['network']['ethernets'][interface]['nat']['status']
                iface['public_ip'] = config_data['network']['ethernets'][interface]['nat']['public_ip']
        
    else:
        print(f"Error: {node_type} in not a valid node type")
    
    check_unconfig_interfaces(filename, node_id, nodes_interfaces_list)


def merge_data() -> None:
    """ Merge the parsed-extracted data from the configuration files with the network topology """
    
    for node in nodes:
        if nodes[node]['node_type'] == "Router":
            nodes[node]['routing_table'] = routing_table_list[node]

    for edge in edges:
        for end, index in zip(['left_end', 'right_end'], [0, 1]):
            node_id = edge.split(' ')[index]
            edges[edge][end] = interfaces[node_id][edges[edge][end]['if_id']]


def export_to_tgf(path: str, topology_no: str) -> None:
    """ Export the network topology with the loaded data to a tgf file """
        
    def export_nodes(output_file):
        """ Export the nodes first"""
        
        # Writing nodes to file   
        for node in nodes:
            if nodes[node]['node_type'] != "Router":
                output_file.write(f"{node} ~ {nodes[node]};\n")
            else:
                output_file.write(f"{node} ~ {'{'}\n")
                for attribute in nodes[node]:
                    if attribute == 'node_type':
                        output_file.write(f"{TAB}'{attribute}' : '{nodes[node][attribute]}',\n")
                    else:
                        output_file.write(f"{TAB}'{attribute}' : {'{'}\n")
                        for rt_attribute in nodes[node][attribute]:
                            output_file.write(f"{TAB}{TAB}'{rt_attribute}' : {nodes[node][attribute][rt_attribute]}")

                            # Do not add write any commas past the last attribute
                            output_file.write(f"{',' * int(rt_attribute != 'next_hop')}\n")
                
                output_file.write(f"{TAB} {'}'} \n {'}'};\n")
    
    def export_edges(output_file):
        """ Export the edges after node export is finished"""
        
        # Writing edges to file
        for edge in edges:
            output_file.write(f"{edge} ~ {'{'}\n")
            for attribute in edges[edge]:
                
                if attribute in {'left_end', 'right_end'}:
                    output_file.write(f"{TAB}'{str(attribute)}' : {edges[edge][attribute]}")
                else:
                    output_file.write(f"{TAB}'{str(attribute)}' : '{edges[edge][attribute]}'")
            
                # Do not add write any commas past the last attribute
                output_file.write(f"{',' * int(attribute != 'latency')}\n")

            output_file.write("};\n\n")
    
    def start_export():
        """ Starts the configurated TGF file  export"""

        with open(f"{path}\\net_topology_{topology_no}.tgf", "w") as output_file:
            export_nodes(output_file)
            output_file.write("\n#\n\n")
            export_edges(output_file)
    
    
    start_export()


def main(topology: str) -> None:
    """ Main function"""
    
    topology_no = topology.split("_")[1]
    filename = f"net_topology_{topology_no}_def.tgf"
    
    # Find examples directory path
    path = find_path(topology, filename)

    # Load the network topology from the tgf file
    parse_net_topology(path, filename)
    
    # Validate that there is a configuration file for every device-node
    nodes_config_exists(path)
    
    # Parse the device configuration files
    parse_config_files(path)

    # Merge data-initialize every device with the data from the configuration files
    merge_data()
    
    # Export the initialized topology to a tgf file
    export_to_tgf(path, topology_no)

    print("Device configuration completed!\n")


def start_device_configuration(topology: str):
    """ The function/interface that is called from the controller"""
    
    main(topology)


if __name__ == '__main__':
    print("Warning: This file is called from the main controller, doesnt run on its own!")