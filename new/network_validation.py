"""
Network Validation ~Under construction!

"""

#Imports
import networkx as nx
import ast
from netaddr import *
import os.path
import re
import pandas as pd
import yaml
import network_renderer as rd
import network_interface as nif


# Global variables
NETWORK_GRAPH = nx.DiGraph()    #network topology graph
HELP_NET_GRAPH = nx.DiGraph()   #help graph used for visualization

#TODO Maybe add the to config file. Acceptable attribute and attribute values
ACCEPTABLE_NODE_ATTR = {
    'node_type' : {'Client_PC', 'Server_PC', 'Router', 'Switch', 'Hub'},
    'routing_table' : {'dest', 'mask', 'next_hop'}
    }
ACCEPTABLE_LINK_ATTR = {'link_ID', 'left_end', 'right_end', 'capacity', 'latency'}
ACCEPTABLE_ADAPTER_ATTR = {
    'Client_PC' : {'if_id', 'mac', 'ip', 'mask', 'gateway', 'dns'},
    'Server_PC' : {'if_id', 'mac', 'ip', 'mask', 'gateway', 'dns'},
    'Router' : {'if_id', 'mac', 'ip', 'mask', 'gateway', 'dns', 'nat'},
    'Switch' : {'if_id', 'mac'},
    'Hub' : {'if_id'}
    }


def parse_tgf_file(path: str, filename: str) -> None:
    """ Parses the configurated .tgf file"""
    
    nodes = []
    edges = []
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
                
                validate_node_attributes(node_id, node_attr)
               
                node_tuple = (node_id, node_attr)
                nodes.append(node_tuple)
                       
            # Parsing edges from file
            else:
                left_end_node_id = line.split("~")[0].split(" ")[0].strip()
                right_end_node_id = line.split("~")[0].split(" ")[1].strip()
                edge_attr = ast.literal_eval(line.split("~")[1].strip())
                
                validate_edge_attributes(nodes, left_end_node_id, right_end_node_id, edge_attr)
                
                edge_tuple = (left_end_node_id, right_end_node_id, edge_attr)
                edges.append(edge_tuple)                         
    
    #Initialize Graphs
    init_graphs(nodes, edges)


def init_graphs(nodes: list, edges: list):
    """ Initializes graphs after parsing is completed 
    Note: It would be better to create routing table Dataframes while parsing
    and add them directly as attributes to graph. But pyvis can not handle them.
    So the NETWORK_GRAPH is first created simply, and then adds the objects as attributes
    
    """
    
    # Creating Networkx Graph
    NETWORK_GRAPH.add_nodes_from(nodes)
    NETWORK_GRAPH.add_edges_from(edges)
    HELP_NET_GRAPH.add_nodes_from(nodes)
    HELP_NET_GRAPH.add_edges_from(edges)

    for node in NETWORK_GRAPH.nodes:
        NETWORK_GRAPH.nodes[node]["network_interfaces"] = []    

    # Create interfaces from edge attributes
    create_interfaces()

    # #Creating routing table dataframes for every Router
    for node in NETWORK_GRAPH:
        if NETWORK_GRAPH.nodes[node]['node_type'] == 'Router':
            routing_table = pd.DataFrame(NETWORK_GRAPH.nodes[node]['routing_table'])
            NETWORK_GRAPH.nodes[node]['routing_table'] = routing_table    
    
    #Create networks subnet table
    create_router_addresses_table()


def validate_node_attributes(node_id: str, node_attr: dict) -> None:
    validate_node_attr_type(node_id, node_attr)


def validate_node_attr_type(node_id: str, node_attr: dict) -> None: 
    """ Validates if the node has the right attributes"""
    
    invalid_node_attr = set(node_attr) - set(ACCEPTABLE_NODE_ATTR)
    
    if invalid_node_attr:
        print("\n  -Node Attribute Type Error: ")
        print(f"  Attributes {invalid_node_attr} are invalid ({node_id})\n")
        exit()

    if 'node_type' not in node_attr:
        print("\n  -Node Attribute Type Error: ")
        print(f"  Attribute node_type is missing from node {node_id}\n")
    
    elif node_attr['node_type'] in ACCEPTABLE_NODE_ATTR['node_type']:
        if node_attr['node_type'] == "Router":
            if 'routing_table' not in node_attr:
                print("\n  -Node Attribute Type Error: ")
                print(f"  Attribute routing_table is missing from node ({node_id})\n")
                exit()
            else:
                validate_routing_table_attr_type(node_id, node_attr)
                validate_routing_table_attr_value(node_id, node_attr)

    else:
        print("Invalid type\n")
        exit()


# TODO: comments
def validate_routing_table_attr_type(node: str, node_attr: dict) -> None:
    """ Validates if the routing table has the right attribues """
    
    missing_table_attr = ACCEPTABLE_NODE_ATTR['routing_table'] - set(node_attr['routing_table'])
    invalid_table_attr = set(node_attr['routing_table']) - ACCEPTABLE_NODE_ATTR['routing_table']
    found_invalid_attr = False

    if missing_table_attr:
        print("\n  -Node Attribute Type Error:")
        print(f"  Attributes {missing_table_attr} are missing from node ({node})\n")
        found_invalid_attr = True
    
    if invalid_table_attr:
        print("\n  -Node Attribute Type Error:")
        print(f"  Attributes {invalid_table_attr} are invalid or misspelled at node ({node})\n")
        found_invalid_attr = True
    
    if found_invalid_attr:
        exit()


# FIXME Write better output messages
def validate_routing_table_attr_value(node_id: str, node_attr: dict) -> None:
    """ Validates if routing tables attribute values are correct"""
    
    dest_count =  len(node_attr['routing_table']['dest'])
    mask_count = len(node_attr['routing_table']['mask'])
    next_hop_count =  len(node_attr['routing_table']['next_hop'])
    
    # Routing table attributes must be of the same length
    if not(dest_count == mask_count == next_hop_count):
        print(f"-Routing table at {node_id} is missing some values\n")
        exit()

    # Destination
    for dest in node_attr['routing_table']['dest']:
        if not is_valid_ip(dest):
            print("  -Routing Table Value Error")
            print(f'{node_id} has destination invalid value\n')
            exit()

    # mask TODO
    for mask in node_attr['routing_table']['mask']:
        if not is_valid_mask(mask) or not is_valid_ip(mask):
            print("  -Routing Table Value Error")
            exit()

    # Next Hop
    for hop in node_attr['routing_table']['next_hop']:
        if not is_valid_ip(hop):
            print("  -Routing Table Value Error")
            print(f'  {node_id} has next hop invalid value\n')
            exit()


def validate_edge_attributes(nodes: list, left_end_node_id: str, right_end_node_id: str, edge_attr: dict) -> None:
    """ Validates the parsed attributes values"""
    
    #Iterating through nodes list to find if left_end and right_end nodes 
    # declared in the file and if true, what type of nodes they are.
    left_end_node_declared = False
    right_end_node_declared = False
    for node in nodes:
        if node[0] == left_end_node_id: 
            left_end_node_declared = True
            left_node_type = node[1]['node_type']

        if node[0] == right_end_node_id:
            right_end_node_declared = True
            right_node_type = node[1]['node_type']
    
    if not left_end_node_declared:
        print(f"Node {left_end_node_id} , at edge {left_end_node_id} { right_end_node_id} is not declared at the tgf file")
        exit()
    
    if not right_end_node_declared:
        print(f"Node {right_end_node_id} , at edge {left_end_node_id} { right_end_node_id} is not declared at the tgf file")
        exit()

    # Global link attributes type validation
    validate_edge_attributes_type(edge_attr, left_end_node_id, right_end_node_id)

    # Global link attributes value validation
    validate_edge_attributes_value(edge_attr, left_end_node_id, right_end_node_id)
    
    # Left-Right End node attributes type validation
    validate_end_node_attributes_type(left_end_node_id, right_end_node_id, left_node_type,'left_end', edge_attr)
    validate_end_node_attributes_type(right_end_node_id, left_end_node_id, right_node_type,'right_end', edge_attr)

    # Left-Right End node attributes value validation
    validate_end_node_attributes_value(left_end_node_id, right_end_node_id, left_node_type, 'left_end', edge_attr)
    validate_end_node_attributes_value(right_end_node_id, left_end_node_id, right_node_type, 'right_end', edge_attr)


def validate_edge_attributes_type(edge_attr: dict, from_node: str, to_node: str) -> None:
    """ Validates if the link has the right attributes
      - A = ACCEPTABLE_LINK_ATTR -> Attributes set a link must have
      - B = edge_attr -> The parsed attribute set
      - A-B = missing_attr_set -> The set of attributes that are missing from the link
      - B-A = invalid_attr_set -> The set of attributes that should not exist on the link
    """

    missing_attr_set = ACCEPTABLE_LINK_ATTR - set(edge_attr)    
    invalid_attr_set = set(edge_attr) - ACCEPTABLE_LINK_ATTR
    found_invalid_parsed_attr = False

    if missing_attr_set:
        print("\n  -Edge Attribute Type Error: ")
        print(f"  Attributes {missing_attr_set} are missing from edge ({from_node + ' ' + to_node})\n")
        found_invalid_parsed_attr = True

    if invalid_attr_set:
        print("\n  -Edge Attribute Type Error: ")
        print(f"  Attributes {invalid_attr_set} are invalid or misspelled at edge ({from_node + ' ' + to_node})\n")
        found_invalid_parsed_attr = True
        
    if found_invalid_parsed_attr:
        exit(0)


# FIXME Break the if statements into smaller functions
def validate_edge_attributes_value(edge_attr: dict, from_node: str, to_node: str) -> None:
    """ Validates if links attributes have the right values"""
    
    # Link ID value validation
    if edge_attr['link_ID'].isdecimal():
        if int(edge_attr['link_ID']) <= 0:
            print("\n  -Edge Attribute Value Error: ")
            print(f"  Invalid link ID value at edge ({from_node + ' ' + to_node})\n")
            exit(0)
    else:
        print("\n -Edge Attribute Value Error: ")
        print(f"  Invalid link ID value at edge ({from_node + ' ' + to_node}) -Must be an integer, greater than 0\n")
        exit(0)
    
    # Capacity value validation
    if edge_attr['capacity'].isdecimal():
        if int(edge_attr['link_ID']) <= 0:
            print("\n  -Edge Attribute Value Error: ")
            print(f"  Invalid link ID value at edge ({from_node + ' ' + to_node})\n")
            exit(0)
    else:
        print("\n  -Edge Attribute Value Error: ")
        print(f"  Invalid capacity value at edge ({from_node + ' ' + to_node}) -Must be an integer, greater than 0\n")
        exit(0)

    # Latency value validation
    if edge_attr['latency'].isdecimal():
        if int(edge_attr['link_ID']) <= 0:
            print("\n  -Edge Attribute Value Error: ")
            print(f"  Invalid link ID value at edge ({from_node + ' ' + to_node})\n")
            exit(0)
    else:
        print("\n  -Edge Attribute Value Error: ")
        print(f"  Invalid latency value at edge ({from_node + ' ' + to_node}) -Must be an integer,greater than 0\n")
        exit(0)


def validate_end_node_attributes_type(from_node: str, to_node: str, node_type: str, end_node: str, edge_attr: dict) -> None:
    """ Validates if the interface has the right attributes"""
    
    if end_node == 'right_end':
        from_node, to_node = to_node, from_node

    # End node attr eg mac,ip etc etc
    valid_adapter_attr_set = ACCEPTABLE_ADAPTER_ATTR[node_type] - set(edge_attr[end_node])
    invalid_adapter_attr_set = set(edge_attr[end_node]) - ACCEPTABLE_ADAPTER_ATTR[node_type]
    found_invalid_adapter_attr = False
    
    if valid_adapter_attr_set:
        found_invalid_adapter_attr = True
        print("\n  -Edge Attribute Type Error: ")
        print(f"  Attributes {valid_adapter_attr_set} are missing from : {from_node}, at edge ({from_node + ' ' + to_node}), with link ID: {edge_attr['link_ID']}\n")
            
    if invalid_adapter_attr_set:
        found_invalid_adapter_attr = True
        print("\n  -Edge Attribute Type Error: ")
        print(f"  Attributes {invalid_adapter_attr_set} should not exist at: {from_node} ,at edge  ({from_node + ' ' + to_node}), with link ID: {edge_attr['link_ID']}\n")
    
    if found_invalid_adapter_attr:
        exit(0)


def validate_end_node_attributes_value(from_node: str, to_node: str, node_type: str, end_node: str, edge_attr: dict) -> None:
    """ Validates if the adapters attributes have the right value """
    
    if end_node == 'right_end':
        from_node, to_node = to_node, from_node

    # Attribute value validation
    if node_type == "Switch":
         #Nodes mac is a valid mac address
        if not is_valid_mac(edge_attr[end_node]['mac']):
            print("\n  -Edge Attribute Value Error: ")
            print(f"  mac addresss  at {from_node}, at edge ({from_node + ' ' + to_node})mac not an acceptable value\n")

    elif node_type in {"Client_PC", "Server_PC", 'Router'}:
        #Nodes mac is a valid mac address
        if not is_valid_mac(edge_attr[end_node]['mac']):
            print("\n  -Edge Attribute Value Error: ")
            print(f"  mac addresss  at {from_node}, at edge ({from_node + ' ' + to_node})mac not an acceptable value\n")
            exit(0)
        #Nodes ip is a valid ip address
        if not is_valid_ip(edge_attr[end_node]['ip']): 
            print("\n  -Edge Attribute Value Error: ")
            print(f"ip addresss  at {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value\n")
            exit(0)
        #mask is a valid ip address and network mask
        if not is_valid_mask(edge_attr[end_node]['mask'] or not is_valid_ip(edge_attr[end_node]['mask'])):
            print("\n  -Edge Attribute Value Error: ")
            print(f"Network mask at {from_node}, at edge ({from_node + ' ' + to_node}) is not a valid Network mask\n")
            exit(0)
        #gateway is a valid ip address
        if not is_valid_ip(edge_attr[end_node]['gateway']):
            print("\n  -Edge Attribute Value Error: ")
            print(f"  gateway's address at {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value\n")
            exit(0)
        #dns is a valid ip address
        if not is_valid_ip(edge_attr[end_node]['dns']):
            print("\n  -Edge Attribute Value Error: ")
            print(f"  dns's addresss  at {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value\n")
            exit(0)

        if node_type == 'Router':
            if edge_attr[end_node]['nat'] not in {'enabled', 'disabled'}:
                print("\n  -Edge Attribute Value Error: ")
                print(f"  nat's value  at {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value\n")
                exit(0)
         

def is_valid_mac(mac: str) -> bool:
    """ Checks if an address is a valid mac address
    
        -A valid mac address consists of 12 hexadecimal digits, organized
        in 6 pairs and those pairs are seperated by  hyphen (-)
    
    """
    
    return bool(re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()))


def is_valid_ip(ip: str) -> bool:
    """ Checks if an address is a valid ip address 
        
        -A valid ip address has length of 32 bit formatted as four 8-bit fields 
        separated by periods.Each 8-bit field represents a byte of the ip address
        Every 8-bit field is written as an integer number of range 0-255
        
        -Eg:
            192.168.1.20 is a valid ip address
            192.168.1.260 in NOT a valid ip address -260 > 255
            192.168.001.20 in NOT a valid ip address -leading zeros in 3rd field
    
    """
    
    addr_fields = ip.split(".")
    if len(addr_fields) != 4 or not all((dest_value.isdecimal()) for dest_value in addr_fields) :
        return False    
    
    return all((int(dest_value) >= 0 and int(dest_value) <= 255 and (len(dest_value.lstrip('0')) == len(dest_value) or len(dest_value) == 1)) for dest_value in addr_fields)


def is_valid_mask(mask: str) -> bool: 
    """ Checks if an address is a valid network mask
        -A network mask is valid if:
            -It is a valid ip address and 
            -It has N ones-1 i a row

        -Eg: 
            - 11111111.11111111.11111111.00000000 is a valid mask
            - 11111111.11111111.11111111.00110000 is NOT a valid mask
    """    
    
    binary_mask =  IPAddress(mask).bits() 
    ones_counter = 0 
    for bit in binary_mask:
        if bit == '1':
            ones_counter += 1
        elif bit == '.':
            continue
        else :  #Found bit 0
            break
    
    return(binary_mask.count('1') == ones_counter)


def create_interfaces() -> None:
    """ Creates the network interface objects from graph's edge attributes 
        
        -Scans through networks edges attributes to extract different
        network interfaces, creates network interface objects and adds them to
        each node, at network_interfaces field 
    """

    for edge in NETWORK_GRAPH.edges: 

        for index, end_node in enumerate(['left_end', 'right_end']):
            node_type = NETWORK_GRAPH.nodes[edge[index]]['node_type']

            if node_type == 'Hub':
                interface = nif.Interface(NETWORK_GRAPH.edges[edge][end_node])

            elif node_type == 'Router':
                interface = nif.RouterInterface(NETWORK_GRAPH.edges[edge][end_node]) 

            elif node_type == 'Switch':
                interface = nif.L2Interface(NETWORK_GRAPH.edges[edge][end_node])

            else:
                interface = nif.PcInterface(NETWORK_GRAPH.edges[edge][end_node])

            # The -not in- is based on the __eq__ func in network interface object 
            if interface not in NETWORK_GRAPH.nodes[edge[index]]['network_interfaces']:
                NETWORK_GRAPH.nodes[edge[index]]['network_interfaces'].append(interface)
            elif node_type in {'Client_PC', 'Server_PC'}: 
                print(f"Warning: Duplicate network interface found on {edge[index]}")
            
            
def create_subnet_mac_table(subnet: nx.DiGraph) -> pd.DataFrame:
    """ Create a table for every mac address there is in a given subnet """
    mac_table_dict = {"Node": [], "mac": []} 
    for node in subnet:
        if subnet.nodes[node]['node_type'] != "Hub":    #No mac for hub
            for interfac in subnet.nodes[node]['network_interfaces']:
                mac_table_dict["Node"].append(node)
                mac_table_dict["mac"].append(str(interfac.mac))

    return pd.DataFrame(mac_table_dict)


def create_router_addresses_table() -> pd.DataFrame:
    """ Table that contains every subnet address on the network """
    
    router_addresses = {}

    for node in NETWORK_GRAPH:
        if NETWORK_GRAPH.nodes[node]['node_type'] == "Router":
            for interface in NETWORK_GRAPH.nodes[node]['network_interfaces']:
                router_addresses[str(interface.ip)] = node
                #router_addresses["Subnet Address"].append(str(interface.ip)) #+ '/' + str(interface.mask.netmask_bits()))
    
    NETWORK_GRAPH.router_addresses = router_addresses
    print(router_addresses)


def create_subnet_ip_table(subnet: nx.DiGraph) -> pd.DataFrame:
    """ Create a table for every ip address there is in a given subnet """
    
    ip_table_dict = {"Node": [], "ip": []}

    for node in subnet.nodes:
        if subnet.nodes[node]['node_type'] in ["Client_PC", "Server_PC", "Router"]:
            for interface in subnet.nodes[node]['network_interfaces']:
                ip_table_dict["Node"].append(node)
                ip_table_dict["ip"].append(str(interface.ip))
            

    return pd.DataFrame(ip_table_dict)


def find_subnets() -> list:
    """ Finds subnets in a given network """
    
    routers=[]
    subnets= []
    G3 = NETWORK_GRAPH.copy()

    # Finds physical subnets by removing router nodes
    for node in list(G3.nodes): 
        if G3.nodes[node]['node_type'] == 'Router':
            routers.append(node)
            G3.remove_node(node)

    # TODO Maybe use generators or yield to save space
    temp_subnets = [G3.subgraph(n) for n in nx.weakly_connected_components(G3)]


    # Adding the router to the subnet it belongs
    for sub in temp_subnets:
        subnet = sub.copy()
        for node in sub.nodes:
            for router in routers:
                
                # Checking if edge (node, router) exists
                if NETWORK_GRAPH.has_edge(node, router):
                    
                    mask = NETWORK_GRAPH.edges[node, router]['right_end']["mask"]
                    nat_enabled = NETWORK_GRAPH.edges[node, router]['right_end']["nat"] == 'enabled'
                    
                    gateway = NETWORK_GRAPH.edges[node, router]['right_end']["ip"]
                    public_address = NETWORK_GRAPH.edges[node, router]['right_end']["ip"]
                    
                    # if nat_enabled:
                    #     gateway =  NETWORK_GRAPH.edges[node, router]['right_end']["private_ip"]
                    #     public_address = NETWORK_GRAPH.edges[node, router]['right_end']["ip"]
                    # else : 
                    #     gateway = NETWORK_GRAPH.edges[node, router]['right_end']["ip"]
                    #     public_address =  gateway

                    router_interface = [nif.RouterInterface(NETWORK_GRAPH.edges[node, router]['right_end'])]
                    subnet.add_nodes_from([(router, {'node_type' : 'Router', 'routing_table' : NETWORK_GRAPH.nodes[router]['routing_table'], 'network_interfaces' : router_interface})])
                    subnet.add_edges_from([(node, router, NETWORK_GRAPH.edges[node, router])])

                 # Checking if edge (router, node) exists
                if NETWORK_GRAPH.has_edge(router, node):
                    
                    mask = NETWORK_GRAPH.edges[router, node]['left_end']["mask"]
                    nat_enabled = NETWORK_GRAPH.edges[router, node]['left_end']["nat"] == 'enabled'

                    gateway = NETWORK_GRAPH.edges[node, router]['right_end']["ip"]
                    public_address = NETWORK_GRAPH.edges[node, router]['right_end']["ip"]
                    
                    # if nat_enabled:
                    #     gateway = NETWORK_GRAPH.edges[router, node]['left_end']["private_ip"]
                    #     public_address = NETWORK_GRAPH.edges[router, node]['left_end']["ip"]
                    # else :
                    #     gateway = NETWORK_GRAPH.edges[router, node]['left_end']["ip"]
                    #     public_address = gateway

                    router_interface = [nif.RouterInterface(NETWORK_GRAPH.edges[node, router]['left_end'])]
                    subnet.add_nodes_from([(router, {'node_type' : 'Router', 'routing_table' : NETWORK_GRAPH.nodes[router]['routing_table'], 'network_interfaces' : router_interface})])
                    subnet.add_edges_from([(router, node, NETWORK_GRAPH.edges[router, node])])

        
        # Checking if subnets router is found
        if not any(subnet.nodes[node]['node_type'] == 'Router' for node in subnet):
            print("Found subnet without a router")
            exit(0)
        
 
        # Adding Subnet's attributes as graph attributes
        subnet.nat_enabled = nat_enabled    # Must be added before creating ip table
        subnet.mac_table = create_subnet_mac_table(subnet)
        subnet.ip_table = create_subnet_ip_table(subnet)
        subnet.gateway = IPAddress(gateway)
        subnet.mask = IPAddress(mask)
        subnet.subnet_address = IPNetwork(gateway + '/' + mask) 

        subnets.append(subnet)
    return subnets    


def is_unique_mac(subnet: nx.DiGraph) -> None:
    """ Checks if there are any duplibate mac addresses in a given subnet"""

    # Dataframe with all the duplicate mac addresses -empty if none duplicate exists-
    duplicate_mac_df = subnet.mac_table[subnet.mac_table.duplicated(["mac"], keep = False)]    
    if not duplicate_mac_df.empty:
        print(f"Found duplicate mac addresses at subnet {str(subnet.gateway)}/{str(subnet.mask.netmask_bits())}: \n{duplicate_mac_df.to_string(index=False)}\n")


def is_unique_subnet() -> None:
    """ Checks if a subnet is unique"""
    


def is_unique_subnet_ip(subnet: nx.DiGraph) -> None:
    """Checks if the ip addresses of the subnet are unique"""
    
    ip_table_df = subnet.ip_table
    duplicate_ip_df = ip_table_df[ip_table_df.duplicated(["ip"], keep = False)]
    
    if not duplicate_ip_df.empty:
        print(f"-Found duplicate ip addresses at subnet {str(subnet.gateway)}/{str(subnet.mask.netmask_bits())}: \n{duplicate_ip_df.to_string(index=False)}\n")


def ip_belongs_at_subnet(subnet: nx.DiGraph) -> None:
    # Checks if ip address belongs at its subnet
    # Find nodes gateway, see if it matches subnets gateway
    # and see if nodes ip belongs at subnet
    
    for node in subnet:
        if subnet.nodes[node]['node_type'] not in ['Switch', 'Hub', 'Router']:
            for i in range(len(subnet.nodes[node]['network_interfaces'])):                    
                nodes_gateway_address = subnet.nodes[node]['network_interfaces'][i].gateway
                
                # Checks if subnets gateway matches the gateway of the rest of the nodes
                if subnet.gateway != nodes_gateway_address:
                    print(f"-gateway error at {node}, routers ip: {subnet.gateway} subnets gateway {nodes_gateway_address}\n")    
                
                ip_address = subnet.nodes[node]['network_interfaces'][i].ip
                subnet_mask = '/' + str(subnet.nodes[node]['network_interfaces'][i].mask.netmask_bits())
                
                # ip belongs at its subnet
                if ip_address not in IPNetwork(str(subnet.gateway) + subnet_mask):
                    print(f"-{node}'s ip address: {str(ip_address)}  does not belong at its subnet {str(subnet.gateway) + subnet_mask}\n")         


def is_unique_network_ip():
    ip_table_df = NETWORK_GRAPH.ip_table
    duplicate_ip_df = ip_table_df[ip_table_df.duplicated(["ip"], keep = False)]
    
    if not duplicate_ip_df.empty:
        print(f"-Found duplicate ip addresses at network \n{duplicate_ip_df.to_string(index=False)}\n")


def validate_routing_tables():
    """
    Validates the routes beetween the nodes
    """
    
    #For every sender node
    for sender_node in NETWORK_GRAPH.nodes:
        if NETWORK_GRAPH.nodes[sender_node]['node_type'] in {"Client_PC", "Server_PC"}:
            
            #For every senders interface (usally only 1)
            for sender_interface in NETWORK_GRAPH.nodes[sender_node]['network_interfaces']:
                
                #For every destination node
                for dest_node in NETWORK_GRAPH.nodes: 
                    if NETWORK_GRAPH.nodes[dest_node]['node_type'] in {"Client_PC", "Server_PC"} and sender_node != dest_node:
                        
                        
                        router_id = NETWORK_GRAPH.router_addresses[str(sender_interface.gateway)]
                        routing_table = NETWORK_GRAPH.nodes[router_id]["routing_table"]


                        #For every destination nodes interface (usually only 1)
                        for dest_interface in NETWORK_GRAPH.nodes[dest_node]['network_interfaces']:
                            
                            #Do not try to find route in nodes that are in the same subnet-YET!
                            if dest_interface.ip in IPNetwork(str(sender_interface.ip) + "/24"):
                                break

                            destination = str(dest_interface.ip)
                            routing_path = [str(sender_interface.ip), str(sender_interface.gateway)]
                            node_path = [sender_node, router_id]
                            dest_found = False
                            loop_found = False

                            while(not(dest_found or loop_found)):

                                dest_entry_in_rt = False
                                dest_entry_value = 0 

                                # Checks if there is an entry for destination in routing table
                                for dest_entry in list(routing_table['dest']):
                                    if destination in IPNetwork(dest_entry + "/" + str(dest_interface.mask.netmask_bits())):
                                        dest_entry_value = dest_entry
                                        dest_entry_in_rt = True

                                # If destination found in routing table, find destinations next hop
                                if dest_entry_in_rt:        
                                    next_hop = routing_table.loc[routing_table['dest'] == dest_entry_value].next_hop.values[0]

                                    # Found loop in the path
                                    if next_hop in routing_path and next_hop != dest_entry:
                                        routing_path.append(next_hop)
                                        loop_found = True
                                        break 
                                    else:
                                        routing_path.append(next_hop)

                                    # Destinations network found
                                    if destination in IPNetwork(next_hop + "/" + str(dest_interface.mask.netmask_bits())):# TODO Use current interfaces mask
                                        dest_found = True
                                    else:
                                        # TODO Check that next_hop is a Router and it is indeed connected to the node!
                                        router = NETWORK_GRAPH.router_addresses[next_hop]
                                        node_path.append(router)
                                        routing_table = NETWORK_GRAPH.nodes[router]["routing_table"]

                                else:
                                    # Did not find destinations entry in routing table, take as next hop tables default gateway 
                                    if "0.0.0.0" in list(routing_table.dest):
                                        next_hop = routing_table.loc[routing_table['dest'] == "0.0.0.0"].next_hop.values[0]
                                    else:
                                        print(f"Did not find entry or default route from {sender_interface.ip} to {destination} on the routing table!")
                                        exit()

                                    router_id = NETWORK_GRAPH.router_addresses[next_hop]
                                    routing_table = NETWORK_GRAPH.nodes[router_id]["routing_table"]
                                    node_path.append(router_id)

                            # 
                            print(f"{sender_node}: {sender_interface.ip} ---> {dest_node}: {dest_interface.ip}")
                            if dest_found:
                                node_path.append(dest_node)
                                #print(f"Found route- {routing_path}")
                                #print(f"FROM: {}")
                                print(f"Path: {node_path}\n")


                            if loop_found:
                                #Found loop
                                print(f"Found loop {node_path}\n")
                            
   
def ip_config() -> None: 
    # Shows every interface
    
    for node in NETWORK_GRAPH.nodes:
        for interface in NETWORK_GRAPH.nodes[node]['network_interfaces']:
            print(f"Node: {node}, Type: {NETWORK_GRAPH.nodes[node]['node_type']}  \n{interface.__str__()}\n")


def find_path(filename: str, example: str) -> str:
    """ Checks that the configurated network topology file exists in examples directory"""
    
    current_directory_path = os.path.dirname(os.path.realpath(__file__))
    examples_directory = current_directory_path + "\\" + "topologies" + "\\" + example
    if filename not in os.listdir(examples_directory):
        print(f"-File {filename} does not exist in current directory\n")
        exit(0)

    return examples_directory


def validate_subnets(network_subnets: list) -> None:
    """
    Through subnet validation we make sure that:
        -Every mac address in a subnet is unique
        -Every ip address in a private network is  private
        -Every ip address in a public network is public 
        -Every node in a subnet has the right gateway 
        -Every ip address in a subnet belongs at its subnet
        -Every ip address in a subnet is unique
    """
    for subnet in network_subnets:
       
       # mac address in a network is unique
        is_unique_mac(subnet)
        
        # ip address in a subnet belongs at its subnet
        ip_belongs_at_subnet(subnet)
        
        # ip address in a subnet is unique
        is_unique_subnet_ip(subnet)


def init_visualization(filename: str):
    """ Visualization initialization
        
        Available aesthetic profiles:
            2D 
                -black_and_white
                -soft_dark
                -total_dark
                -neon_dark
                -classic_blue
                -light_grey_black
                -light_grey_white
                -light_grey_blue
            3D
                # TODO
    """
    
    theme_option = "neon_dark"

    #Load visualization theme config file
    with open("vis_themes.yml", 'r') as cf:		
       
        try:
            vis_theme = yaml.load(cf, Loader = yaml.FullLoader)
        except yaml.YAMLError as exc:
            print(exc)

    
    renderer = rd.Renderer(NETWORK_GRAPH, HELP_NET_GRAPH, vis_theme[theme_option], filename.split('.')[0])
    renderer.render()


#Main funtion
def main(example: str) -> None:
    
    print('\n')

    example_no = example.split("_")[1]
    filename = f"net_topology_{example_no}.tgf"
    
    # Find file in currrent directory
    path = find_path(filename, example)    
        
    # Parse the tgf file
    parse_tgf_file(path, filename)

    # Find network subnets
    network_subnets = find_subnets()

    for sub in network_subnets:
        print(f"Subent address {sub.subnet_address}")
    
    # Validate subnets
    validate_subnets(network_subnets)
    
    #validate_routing_tables
    #validate_routing_tables()
    
    #Show every network interface on the network
    #ip_config()
    
    # Draw network graph
    init_visualization(filename)
    
    


  
