import os
import ast
import yaml
import copy
from netaddr import *



# Constants
TOPOLOGIES_DIRECTORY = 'topologies'
NETWORK_TOPOLOGY = 'network_top1_input.tgf'
EXAMPLE = 'example_1'
TAB = "    "


# Global variables

# Structures for parsed data
nodes = {}
edges = {}
interfaces = {}

# Different types of network interfaces 
interface = {'if_id' : ''}
l2_interface = {'if_id' : '', 'mac' : ''}
pc_interface = {'if_id' : '', 'mac' : '', 'ip' : '', 'mask' : '', 'gateway' : '', 'dns' : ''}
router_interface = {'if_id' : '', 'mac' : '', 'ip' : '', 'mask' : '', 'gateway' : '', 'dns' : '', 'nat' : ''}

node_type_interfaces = {'Hub' : interface, 'Switch' : l2_interface, 'Router' : router_interface, 'Client_PC' : pc_interface, 'Server_PC' : pc_interface }




def find_path() -> str:
    """ Returns examples full directory path """
    
    # The main directory where the scripts are stored
    current_directory_path = os.path.dirname(os.path.realpath(__file__))

    # Checks that topologies directory exists
    if TOPOLOGIES_DIRECTORY not in os.listdir(current_directory_path):
        print(f"Directory error: {TOPOLOGIES_DIRECTORY} directory was not found at {current_directory_path}")
        exit()

    # The directory path where examples are stored
    topologies_path = current_directory_path + "\\" + TOPOLOGIES_DIRECTORY

    # Checks that examples directory exists
    if EXAMPLE not in os.listdir(topologies_path):
        print(f"Directory error: {EXAMPLE} directory was not found at {topologies_path}")
        exit()

    return topologies_path + "\\" + EXAMPLE


def parse_topology(filename: str = NETWORK_TOPOLOGY, path: str = find_path()) -> None:
    """ Parses the .tgf file"""

    line_counter = 0
    nodes_parsing_completed = False

    with open(path + "//" + filename) as f:
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

            # Nodes from  edges seperator in file
            if "#" in line: 
                nodes_parsing_completed = True
                continue
                        
            # Read until ; character is read          
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
                #edge_tuple = (left_end_node_id, right_end_node_id, edge_attr)
                #edges.append(edge_tuple)
                key = f"{left_end_node_id} {right_end_node_id}"               
                edges[key] = edge_attr


def parse_config_files(path: str = find_path()) -> None:
    """ Parses the configuration files for network devices"""
    
    for filename in os.listdir(path):
        
        if filename.split(".")[1] == "yml":
            with open(path + "\\" + filename, "r") as stream:
                try:
                    config_data = yaml.load(stream, Loader = yaml.FullLoader)
                    node_id = filename.split("_")[0]
                except yaml.YAMLError as exc:
                    print(exc)
            
            extract_data_from_config(node_id, config_data)
                        

def extract_data_from_config(node_id: str, config_data: dict) -> None:
    """ Extract interfaces data """

    node_type = nodes[node_id]['node_type']
    for interface in config_data['network']['ethernets']:
        my_interface = copy.deepcopy(node_type_interfaces[node_type])
        interfaces[interface] = my_interface

        my_interface['if_id'] = interface
        if node_type == 'Hub':
            pass

        elif node_type == 'Switch':
            my_interface['mac'] = config_data['network']['ethernets'][interface]['macaddress']

        elif node_type in {'Client_PC', 'Server_PC', 'Router'}:
            my_interface['mac'] = config_data['network']['ethernets'][interface]['macaddress']
            my_interface['ip'] = config_data['network']['ethernets'][interface]['addresses'].split('/')[0]
            my_interface['mask'] = config_data['network']['ethernets'][interface]['addresses'].split('/')[1]
            my_interface['gateway'] = config_data['network']['ethernets'][interface]['gateway4']
            my_interface['dns'] = config_data['network']['ethernets'][interface]['nameservers']['addresses'][0]

            if node_type == "Router":
                #See if it is a NAT or not
                my_interface['nat'] = 'enabled' if IPAddress(my_interface['ip']).is_private() else 'disabled'

        else:
            print(f"Error: {node_type} in not a valid node type")
    

def merge_data() -> None:
    """ Adds the parsed config files data at edges """
    
    for edge in edges:
        for end in ['left_end', 'right_end']:
            edges[edge][end] = interfaces[edges[edge][end]['if_id']]


def export_to_tgf() -> None:
    """ Export network to tgf """

    # Writing nodes to file   
    output_file = open("out", "w")
    for node in nodes:
        output_file.write(f"{node} ~ {nodes[node]};\n")
        
    # Nodes from edges seperator
    output_file.write("\n#\n\n")
    
    # Writing edges to file
    for edge in edges:
        output_file.write(f"{edge} ~ {'{'}\n")
        for attribute in edges[edge]:
           output_file.write(f"{TAB}'{str(attribute)}' : {edges[edge][attribute]}\n")

        output_file.write("};\n\n")
    
    output_file.close()


def main():
    """ Main function"""
    
    parse_topology()
  
    parse_config_files()

    merge_data()
    
    export_to_tgf()

    print(f"Nodes: {nodes}\n")
    print(f"Edges: {edges}\n")
    print(f"Interfaces: {interfaces}\n")

    

if __name__ == '__main__':
    main()

