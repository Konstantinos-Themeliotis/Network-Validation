import os
import ast
import yaml
import copy
from netaddr import *


# Constants
TOPOLOGIES_DIRECTORY = 'topologies' # The directory were every example is stored
TAB = "    "


# Global variables

# Structures for parsed data
nodes = {}
edges = {}
interfaces = {}         #All the interfaces parsed from configuration files
node_interfaces = {}    #Every nodes interfaces defined in network topology tgf file

#Routing table
routing_table = {"dest" : [], "mask" : [], "next_hop" : []}
routing_table_list = {}

# Template for different types of network interfaces 
interface = {'if_id' : ''}
l2_interface = {'if_id' : '', 'mac' : ''}
pc_interface = {'if_id' : '', 'mac' : '', 'ip' : '', 'mask' : '', 'gateway' : '', 'dns' : ''}
router_interface = {'if_id' : '', 'mac' : '', 'ip' : '', 'mask' : '', 'gateway' : '', 'dns' : '', 'nat' : ''}

node_type_interfaces = {'Hub' : interface, 'Switch' : l2_interface, 'Router' : router_interface, 'Client_PC' : pc_interface, 'Server_PC' : pc_interface }




def find_path(example: str, filename: str) -> str:
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
    if example not in os.listdir(topologies_path):
        print(f"Directory error: {example} directory was not found at {topologies_path}")
        exit()
    
    examples_path = topologies_path + "\\" + example

    # Checks that network topology defition exists
    if filename not in os.listdir(examples_path):
        print(f"File Error: Examples {example} network topology definition {filename} does not exist at: {examples_path}")
        exit()
    
    return examples_path 


def parse_net_topology(path: str, filename: str) -> None:
    """ Parses the networks topology that is defined at a tgf file"""

    line_counter = 0
    nodes_parsing_completed = False

    with open(path + "\\" + filename) as f:
        while True:    
            # Reading the file line-line
            line = f.readline()
            line_counter += 1
            
            # End of file
            if not line:
                break
            
            # Blank Line
            if line.isspace():
                continue

            # Nodes from  edges seperator in tgf file
            if "#" in line: 
                nodes_parsing_completed = True
                continue
                        
            # Read until ";" character is read          
            while ";" not in line:
                new_line = f.readline()
                line_counter += 1
                
                if not new_line:
                    print(f"\n  File {filename}, line {line_counter-1}")
                    print("  SyntaxError: Break char ';' is missing\n")
                    exit()
                
                if new_line.isspace():
                    print(f"\n  File {filename}, line {line_counter-1}")
                    print("  SyntaxError: Found newline before break char ';' or is missing \n")
                    exit()
                line += new_line
            
            line = line.strip(";\n")
                
            
            # Parsing nodes from file      
            if not nodes_parsing_completed: 
                node_id = line.split("~")[0].strip()  
                node_attr = ast.literal_eval(line.split("~")[1].strip())
                nodes[node_id] = node_attr
                       
            # Parsing edges from file
            else:
                left_end_node_id = line.split("~")[0].split(" ")[0].strip()
                right_end_node_id = line.split("~")[0].split(" ")[1].strip()
                edge_attr = ast.literal_eval(line.split("~")[1].strip())                
                key = f"{left_end_node_id} {right_end_node_id}"               
                edges[key] = edge_attr

            # Group each nodes interfaces together
            group_nodes_interfaces()


def nodes_config_exists(path: str) -> None:
    """ Checks that there is a configuration file for each node-device"""
    
    config_files_set = set([x.split("_")[0] for x in os.listdir(path) if x.split(".")[1] == 'yml'])
    missing_config_nodes = set(nodes) - config_files_set
    if missing_config_nodes:
        print(f"Initialization error: Did not find any interface configuration file for this nodes: {missing_config_nodes}")
        exit()


def group_nodes_interfaces() -> None:
    """ Groups together the interfaces of every node, found on the tgf file"""
    
    for node in nodes:
        node_interfaces[node] = []
    
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
            
            extract_data_from_config(node_id, config_data)


def check_unconfig_interfaces(node_id: str, nodes_interfaces_list: list) -> None:
    """ Checks for any defined interface in the tgf that has not been configured"""
    
    missing_interfaces = set(node_interfaces[node_id]) - set(nodes_interfaces_list)
    if missing_interfaces:
        print(f"Initialaization error: {missing_interfaces}")
        exit()


def extract_data_from_config(node_id: str, config_data: dict) -> None:
    """ Extracts the needed data from every interface defined in the configuration file 
        that later will initialize the devices defined in the tgf file
    """
    
    node_type = nodes[node_id]['node_type']
    nodes_interfaces_list = []
    
    def init_interface():
        """ 
            Initialize an interface from the template for every interface
            in the configuration file
        """

        my_interface = copy.deepcopy(node_type_interfaces[node_type])
        interfaces[interface] = my_interface
        nodes_interfaces_list.append(interface)
        my_interface['if_id'] = interface
        return my_interface
        
    
    if node_type == 'Hub':
        pass

    elif node_type == 'Switch':
        for interface in config_data['network']['ethernets']:
            iface = init_interface()
            iface['mac'] = config_data['network']['ethernets'][interface]['macaddress']

    elif node_type in {'Client_PC', 'Server_PC'}:
        for interface in config_data['network']['ethernets']:
            iface = init_interface()
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
                iface = init_interface()
                iface['mac'] = config_data['network']['ethernets'][interface]['macaddress']
                iface['ip'] = config_data['network']['ethernets'][interface]['addresses'].split('/')[0]
                mask = config_data['network']['ethernets'][interface]['addresses'].split('/')[1]
                iface['mask'] = str(IPNetwork(f"0.0.0.0/{mask}").netmask)
                iface['gateway'] = config_data['network']['ethernets'][interface]['gateway4']
                iface['dns'] = config_data['network']['ethernets'][interface]['nameservers']['addresses'][0]
                
                #See if it is a NAT or not
                iface['nat'] = 'enabled' if IPAddress(iface['ip']).is_private() else 'disabled'
        
    else:
        print(f"Error: {node_type} in not a valid node type")
    
    check_unconfig_interfaces(node_id, nodes_interfaces_list)


def merge_data() -> None:
    """ Merge the parsed-extracted data from the configuration files with the network topology """
    
    for node in nodes:
        if nodes[node]['node_type'] == "Router":
            nodes[node]['routing_table'] = routing_table_list[node]

    for edge in edges:
        for end in ['left_end', 'right_end']:
            edges[edge][end] = interfaces[edges[edge][end]['if_id']]


def export_to_tgf(path: str, example_no: str) -> None:
    """ Export the network topology with the loaded data to a tgf file """
    
    output_file = open(f"{path}\\net_topology_{example_no}.tgf", "w")
    
    def export_nodes():
        
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
    
    def export_edges():
        
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
        export_nodes()
        output_file.write("\n#\n\n")
        export_edges()
        output_file.close()
    
    start_export()


def main(example: str) -> None:
    """ Main function"""
    
    example_no = example.split("_")[1]
    filename = f"net_topology_{example_no}_def.tgf"
    
    # Find examples directory path
    path = find_path(example, filename)

    # Load the network topology from the tgf file
    parse_net_topology(path, filename)
    
    # Validate that there is a configuration file for every device-node
    nodes_config_exists(path)

    # Parse the device configuration files
    parse_config_files(path)

    # Merge data-initialize every device with the data from the configuration files
    merge_data()
    
    # Export the initialized topology to a tgf file
    export_to_tgf(path, example_no)

    print("Device configuration completed!")
