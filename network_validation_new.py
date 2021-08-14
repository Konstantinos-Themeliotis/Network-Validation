"""
Network Validation ~Under construction!
    
    -Things TODO now:
        -Routing table validation

    -Things TODO later:
        -Export to yaml format
    
    -Vizual:
        -Terminal output decorator 

    -Refactoring:
        -Add IP and MAC addresses in the same dataframe
        -Create an error handling function or class
        -Maybe create an object builder
        -Maybe create some classes and take advantage of software patterns
    
    -Small details TODO:
        -Check at value validation if is written correctly in the file
            -Eg if link_ID is writter as string in te file or not

"""

#Imports
import networkx as nx
import ast
import network_adapter as na
from netaddr import IPNetwork, IPAddress
import os.path
import re
import pandas as pd
import yaml
import network_renderer as rd


# Global variables
NETWORK_GRAPH = nx.DiGraph()    #network topology graph
HELP_NET_GRAPH = nx.DiGraph()

#Acceptable attribute and attribute values
ACCEPTABLE_NODE_ATTR = {
    'node_type' : set(['Client_PC', 'Server_PC', 'Router', 'Switch', 'Hub']),
    'routing_table' : set(['dest', 'mask', 'link', 'next_hop'])
    }
ACCEPTABLE_LINK_ATTR = set(('link_ID', 'left_end', 'right_end', 'capacity', 'latency'))
ACCEPTABLE_ADAPTER_ATTR = {
    'Client_PC' : set(['MAC', 'IP', 'Mask', 'Gateway', 'DNS']),
    'Server_PC' : set(['MAC', 'IP', 'Mask', 'Gateway', 'DNS']),
    'Router' : set(['MAC', 'IP', 'Mask', 'Gateway', 'DNS', 'NAT', 'private_IP']),
    'Switch' : set(['MAC']),
    'Hub' : set(['msg'])}


def parse_tgf_file(filename: str) -> None:
    """ Parses the .tgf file"""
    
    nodes = []
    edges = []
    line_counter = 0
    nodes_parsing_completed = False

    with open(filename) as f:
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
            
            if "#Nodes" in line:
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
    routing_table_list = []
    
    # Creating Networkx Graph
    NETWORK_GRAPH.add_nodes_from(nodes)
    NETWORK_GRAPH.add_edges_from(edges)
    
    HELP_NET_GRAPH.add_nodes_from(nodes)
    HELP_NET_GRAPH.add_edges_from(edges)
    

    create_adapters()

    # #Creating routing table dataframes
    # for node in NETWORK_GRAPH:
    #     if NETWORK_GRAPH.nodes[node]['node_type'] == 'Router':
    #         routing_table = pd.DataFrame(NETWORK_GRAPH.nodes[node]['routing_table'])
    #         NETWORK_GRAPH.nodes[node]['routing_table'] = routing_table
    #         routing_table_dict = {"Node" : node, "routing_table" : routing_table}
    #         routing_table_list.append(routing_table_dict)

    # # Adding routing tables as NETWORK_GRAPHS attributes
    # NETWORK_GRAPH.routing_table_list = routing_table_list

    # #Creating network adapter objects   

    # #Create networks subnet table
    # create_network_sub_table()
    # Adding network_interfaces attribute to graph
    for node in NETWORK_GRAPH.nodes: 
        NETWORK_GRAPH.nodes[node]["network_interfaces"] = []
    

def validate_node_attributes(node_id: str, node_attr: dict) -> None:
    validate_node_attr_type(node_id, node_attr)
    #validate_routing_table_attr_value(node, node_attr)  Called from somewhere else


def validate_node_attr_type(node_id: str, node_attr: dict) -> None: 
    """ Validates if the node has the right attributes"""
    
    invalid_node_attr = set(node_attr) - set(ACCEPTABLE_NODE_ATTR)
    
    if invalid_node_attr:
        print("\n  -Node Attribute Type Error: ")
        print(f"  Attributes {invalide_node_attr} are invalid ({node_id})\n")
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
        print(f"  Attributes {missing_table_attr} are missing from node ({node_id})\n")
        found_invalid_attr = True
    
    if invalid_table_attr:
        print("\n  -Node Attribute Type Error:")
        print(f"  Attributes {invalid_table_attr} are invalid or misspelled at node ({node_id})\n")
        found_invalid_attr = True
    
    if found_invalid_attr:
        exit()


# FIXME Write better output messages
def validate_routing_table_attr_value(node_id: str, node_attr: dict) -> None:
    """ Validates if routing tables attribute values are correct"""
    
    dest_count =  len(node_attr['routing_table']['dest'])
    mask_count = len(node_attr['routing_table']['mask'])
    link_count = len( node_attr['routing_table']['link'])
    next_hop_count =  len(node_attr['routing_table']['next_hop'])
    
    # Routing table attributes must be of the same length
    if not(dest_count == mask_count == link_count == next_hop_count):
        print(f"-Routing table at {node_id} is missing some values\n")

    # Destination
    for dest in node_attr['routing_table']['dest']:
        if not is_valid_ip(dest):
            print("  -Routing Table Value Error")
            print(f'{node_id} has destination invalid value\n')
            exit()

    # Mask TODO
    for mask in node_attr['routing_table']['mask']:
        if not is_valid_mask(mask) or not is_valid_ip(mask):
            print("  -Routing Table Value Error")
            exit()

    # Link
    for link in node_attr['routing_table']['link']:
        if link.isdecimal() and int(link) <= 0 or not link.isdecimal():
            print("\n  -Routing Table Value Error: ")
            print(f"  Invalid link ID value at routing table at {node_id})\n")
            exit()
    
    # Next Hop
    for hop in node_attr['routing_table']['next_hop']:
        if not is_valid_ip(hop):
            print("  -Routing Table Value Error")
            print(f'  {node_id} has next hop invalid value\n')
            exit()


def validate_edge_attributes(nodes: list, left_end_node: str, right_end_node: str, edge_attr: dict) -> None:
    """ Validates the parsed attributes values"""
    
    for node in nodes:
        if node[0] == left_end_node: 
            left_node_type = node[1]['node_type']

        if node[0] == right_end_node:
            right_node_type = node[1]['node_type']
    
    # Global link attributes type validation
    validate_edge_attributes_type(edge_attr, left_end_node, right_end_node)

    # Global link attributes value validation
    validate_edge_attributes_value(edge_attr, left_end_node, right_end_node)
    
    # Left-Right End node attributes type validation
    validate_end_node_attributes_type(left_end_node, right_end_node, left_node_type,'left_end', edge_attr)
    validate_end_node_attributes_type(right_end_node, left_end_node, right_node_type,'right_end', edge_attr)

    # Left-Right End node attributes value validation
    validate_end_node_attributes_value(left_end_node, right_end_node, left_node_type, 'left_end', edge_attr)
    validate_end_node_attributes_value(right_end_node, left_end_node, right_node_type, 'right_end', edge_attr)


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
    """ Validates if the adapter has the right attributes"""
    
    if end_node == 'right_end':
        from_node, to_node = to_node, from_node

    # End node attr eg MAC,IP etc etc
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
         #Nodes MAC is a valid MAC address
        if not is_valid_mac(edge_attr[end_node]['MAC']):
            print("\n  -Edge Attribute Value Error: ")
            print(f"  MAC addresss  at {from_node}, at edge ({from_node + ' ' + to_node})mac not an acceptable value\n")

    elif node_type in {"Client_PC", "Server_PC", 'Router'}:
        #Nodes MAC is a valid MAC address
        if not is_valid_mac(edge_attr[end_node]['MAC']):
            print("\n  -Edge Attribute Value Error: ")
            print(f"  MAC addresss  at {from_node}, at edge ({from_node + ' ' + to_node})mac not an acceptable value\n")
            exit(0)
        #Nodes IP is a valid IP address
        if not is_valid_ip(edge_attr[end_node]['IP']): 
            print("\n  -Edge Attribute Value Error: ")
            print(f"IP addresss  at {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value\n")
            exit(0)
        #Mask is a valid IP address and network mask
        if not is_valid_mask(edge_attr[end_node]['Mask'] or not is_valid_ip(edge_attr[end_node]['Mask'])):
            print("\n  -Edge Attribute Value Error: ")
            print(f"Network Mask at {from_node}, at edge ({from_node + ' ' + to_node}) is not a valid Network Mask\n")
            exit(0)
        #Gateway is a valid IP address
        if not is_valid_ip(edge_attr[end_node]['Gateway']):
            print("\n  -Edge Attribute Value Error: ")
            print(f"  Gateway's address at {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value\n")
            exit(0)
        #DNS is a valid IP address
        if not is_valid_ip(edge_attr[end_node]['DNS']):
            print("\n  -Edge Attribute Value Error: ")
            print(f"  DNS's addresss  at {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value\n")
            exit(0)

        if node_type == 'Router':
            if not is_valid_nat_opt(edge_attr[end_node]['NAT']):
                print("\n  -Edge Attribute Value Error: ")
                print(f"  NAT's value  at {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value\n")
                exit(0)
            if not  is_valid_ip(edge_attr[end_node]['private_IP']):
                print("\n  -Edge Attribute Value Error: ")
                print(f"  private_IP value at {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value\n")
                exit(0)


def is_valid_mac(mac: str) -> bool:
    """ Checks if an address is a valid MAC address """
    # TODO Regex to be explained
    return bool(re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()))


def is_valid_ip(ip: str) -> bool:
    """ Checks if an address is a valid IP address 
        
        -A valid IP address has length of 32 bit formatted as four 8-bit fields 
        separated by periods.Each 8-bit field represents a byte of the IP address
        Every 8-bit field is written as an integer number of range 0-255
        
        -Eg:
            192.168.1.20 is a valid IP address
            192.168.1.260 in NOT a valid IP address -260 > 255
            192.168.001.20 in NOT a valid IP address -leading zeros in 3rd field
    
    """
    
    addr_fields = ip.split(".")
    if len(addr_fields) != 4 or not all((x.isdecimal()) for x in addr_fields) :
        return False    
    
    return all((int(x) >= 0 and int(x) <= 255 and (len(x.lstrip('0')) == len(x) or len(x) == 1)) for x in addr_fields)


def is_valid_mask(mask: str) -> bool: 
    """ Checks if an address is a valid network Mask
        -A network mask is valid if:
            -It is a valid IP address and 
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


def is_valid_nat_opt(NAT: str) -> bool:
    """ Checks if nat option in valid
        NAT option in a Router should ne enabled or disabled
    
    """
    return NAT in {'enabled', 'disabled'}
    

def create_interfaces() -> None:
    """ Creates the network interface objects from graph's edge attributes 
        
        -Scans through networks edges attributes to extract different
        network interfaces, creates network interface objects and adds them to
        each node, at network_interfaces field 
    """

    end_nodes = ['left_end', 'right_end']
    for edge in NETWORK_GRAPH.edges: 

        for index, end_node in enumerate(end_nodes):
            node_type = NETWORK_GRAPH.nodes[edge[index]][end_node]

            if node_type == 'Hub':
                interface = ni.Interface(NETWORK_GRAPH.edges[edge][end_node])

            elif node_type == 'Router':
                interface = ni.RouterInterface(NETWORK_GRAPH.edges[edge][end_node]) 

            elif node_type == 'Switch':
                interface = ni.L2Interface(NETWORK_GRAPH.edges[edge][end_node])

            else:
                interface = ni.PcInterface(NETWORK_GRAPH.edges[edge][end_node])

        if interface not in NETWORK_GRAPH.nodes[edge[index]]['network_interfaces']:
            NETWORK_GRAPH.nodes[edge[index]]['network_interfaces'].append(interface)
        elif node_type in {'Client_PC', 'Server_PC'}: 
            print(f"Warning: Duplicate network interface found on {edge[index]}")
        

def create_subnet_mac_table(subnet: nx.DiGraph) -> pd.DataFrame:
    """ Create a table for every MAC address there is in a given subnet """
    
    mac_table_dict = {"Node": [], "MAC": []}
    for node in subnet:
        if subnet.nodes[node]['node_type'] != "Hub":
            for adapter in subnet.nodes[node]['network_adapters']:
                mac_table_dict["Node"].append(node)
                mac_table_dict["MAC"].append(str(adapter.MAC))

    return pd.DataFrame(mac_table_dict)


def create_network_sub_table() -> pd.DataFrame:
    """ Table that contains every subnet address on the network """
    
    sub_table_dict = {"Subnet Address": [], "Router": []}

    for node in NETWORK_GRAPH:
        if NETWORK_GRAPH.nodes[node]['node_type'] == "Router":
            for adapter in NETWORK_GRAPH.nodes[node]['network_adapters']:
                sub_table_dict["Subnet Address"].append(str(adapter.IP) + '/' + str(adapter.Mask.netmask_bits()))
                sub_table_dict["Router"].append(node)
    
    NETWORK_GRAPH.network_sub_table = pd.DataFrame(sub_table_dict)


def create_subnet_ip_table(subnet: nx.DiGraph) -> pd.DataFrame:
    """ Create a table for every IP address there is in a given subnet """
    
    ip_table_dict = {"Node": [], "IP": []}

    for node in subnet.nodes:
        if subnet.nodes[node]['node_type'] in ["Client_PC", "Server_PC", "Router"]:
            for adapter in subnet.nodes[node]['network_adapters']:
                ip_table_dict["Node"].append(node)
                ip_table_dict["IP"].append(str(adapter.IP))
            
            #Add routers private ip to ip table
            if subnet.nat_enabled:
                ip_table_dict["Node"].append(node)
                ip_table_dict["IP"].append(str(adapter.private_IP))

    return pd.DataFrame(ip_table_dict)


#TODO add comments and maybe break the functions
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
                
                if NETWORK_GRAPH.has_edge(node, router):
                    
                    mask = NETWORK_GRAPH.edges[node, router]['right_end']["Mask"]
                    nat_enabled = NETWORK_GRAPH.edges[node, router]['right_end']["NAT"] == 'enabled'

                    if nat_enabled:
                        gateway =  NETWORK_GRAPH.edges[node, router]['right_end']["private_IP"]
                        public_address = NETWORK_GRAPH.edges[node, router]['right_end']["IP"]
                    else : 
                        gateway = NETWORK_GRAPH.edges[node, router]['right_end']["IP"]
                        public_address =  gateway

                    router_adapter = [na.RouterAdapter(
                                NETWORK_GRAPH.edges[node, router]['right_end']["MAC"], NETWORK_GRAPH.edges[node, router]['right_end']["IP"], 
                                NETWORK_GRAPH.edges[node, router]['right_end']["Mask"], NETWORK_GRAPH.edges[node, router]['right_end']["Gateway"], 
                                NETWORK_GRAPH.edges[node, router]['right_end']["DNS"], NETWORK_GRAPH.edges[node, router]['right_end']["NAT"],  
                                NETWORK_GRAPH.edges[node, router]['right_end']["private_IP"])]


                    subnet.add_nodes_from([(router, {'node_type' : 'Router', 'routing_table' : NETWORK_GRAPH.nodes[router]['routing_table'], 'network_adapters' : router_adapter})])
                    subnet.add_edges_from([(node, router, NETWORK_GRAPH.edges[node, router])])

                if NETWORK_GRAPH.has_edge(router, node):
                    
                    mask = NETWORK_GRAPH.edges[router, node]['left_end']["Mask"]
                    nat_enabled = NETWORK_GRAPH.edges[router, node]['left_end']["NAT"] == 'enabled'
                    
                    if nat_enabled:
                        gateway = NETWORK_GRAPH.edges[router, node]['left_end']["private_IP"]
                        public_address = NETWORK_GRAPH.edges[router, node]['left_end']["IP"]
                    else :
                        gateway = NETWORK_GRAPH.edges[router, node]['left_end']["IP"]
                        public_address = gateway

                    router_adapter = [na.RouterAdapter(
                                NETWORK_GRAPH.edges[router, node]['left_end']["MAC"], NETWORK_GRAPH.edges[router, node]['left_end']["IP"], 
                                NETWORK_GRAPH.edges[router, node]['left_end']["Mask"], NETWORK_GRAPH.edges[router, node]['left_end']["Gateway"], 
                                NETWORK_GRAPH.edges[router, node]['left_end']["DNS"], NETWORK_GRAPH.edges[router, node]['left_end']["NAT"],  
                                NETWORK_GRAPH.edges[router, node]['left_end']["private_IP"])]

                    subnet.add_nodes_from([(router, {'node_type' : 'Router', 'routing_table' : NETWORK_GRAPH.nodes[router]['routing_table'], 'network_adapters' : router_adapter})])
                    subnet.add_edges_from([(router, node, NETWORK_GRAPH.edges[router, node])])

        if not has_router(subnet):
            print("Found subnet without a router")
            exit(0)
        
 
        # Subnets attributes as graph attributes
        subnet.nat_enabled = nat_enabled    # Must be added before creating ip table
        subnet.mac_table = create_subnet_mac_table(subnet)
        subnet.ip_table = create_subnet_ip_table(subnet)
        subnet.public_address = public_address
        subnet.gateway = IPAddress(gateway)
        subnet.mask = IPAddress(mask)

        subnets.append(subnet)

    return subnets    

    
def has_router(subnet: nx.DiGraph) -> bool:
    """Checks if every subnet has a router-gateway"""
    return any(subnet.nodes[node]['node_type'] == 'Router' for node in subnet)


def is_unique_linkID() -> None:
    """ Checks if every link ID in the network is unique """
    
    edge_list = list(NETWORK_GRAPH.edges)
    for index, edge in enumerate(NETWORK_GRAPH.edges):
        for i in range(index+1, len(edge_list)):
            if NETWORK_GRAPH.edges[edge]['link_ID'] == NETWORK_GRAPH.edges[edge_list[i]]['link_ID']:
                print(f"Found duplicate link ID at edges {edge}, {edge_list[i]}. Link ID must be unique \n")


def is_unique_mac(subnet: nx.DiGraph) -> None:
    """ Checks if there are any duplibate MAC addresses in a given subnet"""

    mac_table_df = subnet.mac_table
    duplicate_mac_df = mac_table_df[mac_table_df.duplicated(["MAC"], keep = False)]
    
    if not duplicate_mac_df.empty:
        print(f"Found duplicate MAC addresses at subnet {str(subnet.gateway)}/{str(subnet.mask.netmask_bits())}: \n{duplicate_mac_df.to_string(index=False)}\n")


def is_unique_subnet_ip(subnet: nx.DiGraph) -> None:
    """Checks if the IP addresses of the subnet are unique"""
    
    ip_table_df = subnet.ip_table
    duplicate_ip_df = ip_table_df[ip_table_df.duplicated(["IP"], keep = False)]
    
    if not duplicate_ip_df.empty:
        print(f"-Found duplicate IP addresses at subnet {str(subnet.gateway)}/{str(subnet.mask.netmask_bits())}: \n{duplicate_ip_df.to_string(index=False)}\n")


def ip_belongs_at_subnet(subnet: nx.DiGraph) -> None:
    # Checks if IP address belongs at its subnet
    # Find nodes gateway, see if it matches subnets gateway
    # and see if nodes IP belongs at subnet
    for node in subnet:
        if subnet.nodes[node]['node_type'] not in ['Switch', 'Hub', 'Router']:
            for i in range(len(subnet.nodes[node]['network_adapters'])):                    
                nodes_gateway_address = subnet.nodes[node]['network_adapters'][i].Gateway
                
                # Checks if subnets gateway matches the gateway of the rest of the nodes
                if subnet.gateway != nodes_gateway_address:
                    print(f"-Gateway error at {node}, routers IP: {subnet.gateway} subnets gateway {nodes_gateway_address}\n")    
                
                ip_address = subnet.nodes[node]['network_adapters'][i].IP
                subnet_mask = '/' + str(subnet.nodes[node]['network_adapters'][i].Mask.netmask_bits())
                
                # IP belongs at its subnet
                if ip_address not in IPNetwork(str(subnet.gateway) + subnet_mask):
                    print(f"-{node}'s IP address: {str(ip_address)}  does not belong at its subnet {str(subnet.gateway) + subnet_mask}\n")         


def has_valid_private_addr(subnet: nx.DiGraph) -> None:
    """
    Checks if an address in a NAT network is private or not
    in a given private (NAT) network
      
      Private address prefixes:
          10/8  
          172.16/12    
          192.168/16
    
    """
    for index, row in subnet.ip_table.iterrows():
        ip_address = IPAddress(str(row.IP))
        
        # Subnets public IP should not be private 
        if str(ip_address) == subnet.public_address:
            if ip_address.is_private():
                print("-Routers public IP should be public\n")
                continue    # next ip
        
        if not IPAddress(str(row.IP)).is_private():
            print("-Found non private IP addresses in a private network\n")
            print(subnet.ip_table.loc[[index]])    


def has_valid_public_addr(subnet: nx.DiGraph) -> None:
    """
    Checks if an address is public address or not 
    in a given public network (non-NAT)
    """
    for index, row in subnet.ip_table.iterrows():
        
        ip_address = IPAddress(str(row.IP))
        
        if IPAddress(str(row.IP)).is_private():
            print("-Found private IP addresses in a non-private network\n")
            print(subnet.ip_table.loc[[index]])    
    

def is_unique_network_ip():
    ip_table_df = NETWORK_GRAPH.ip_table
    duplicate_ip_df = ip_table_df[ip_table_df.duplicated(["IP"], keep = False)]
    
    if not duplicate_ip_df.empty:
        print(f"-Found duplicate IP addresses at network \n{duplicate_ip_df.to_string(index=False)}\n")


def validate_routing_tables():
    """
    -Validate destination: Make sure that destination exists in the network
    -Validate link: Make sure that the link/interface exists in the network
    -Validate next_hop : Make sure that next_hop/gateway/linkID exists in the network
    """
    
    for routing_table_dict in NETWORK_GRAPH.routing_table_list:
        routing_dest_exists(routing_table_dict['routing_table'].dest)
        routing_link_exists(routing_table_dict['routing_table'].link)
        routing_next_hop_exists(routing_table_dict['routing_table'].next_hop)


def routing_dest_exists(destinations: pd.Series):
   """ Validates that a destination in routing table exists """
   

def routing_link_exists(links):
    """ Validates that a link/interface in the network exists"""
    link_list = []
    for edge in NETWORK_GRAPH.edges:
        link_list.append(NETWORK_GRAPH.edges[edge]['link_ID'])
    
    for link in links:
        if link not in link_list:
            print(f"Link ID {link} does not exist in network")


def routing_next_hop_exists(next_hops: pd.Series):
    """ Validates that the next hop in the network exists """
    
    for hop in next_hops:
        if hop not in NETWORK_GRAPH.ip_table.IP.values:
            print(f"Next_hop: {hop} not found in network")
            exit()


def ip_config() -> None: 
    # Shows every adapter
    
    for node in NETWORK_GRAPH.nodes:
        for i in range(len(NETWORK_GRAPH.nodes[node]['network_adapters'])) :
            print(f"Node: {node}, Type: {NETWORK_GRAPH.nodes[node]['node_type']}  \n{NETWORK_GRAPH.nodes[node]['network_adapters'][i].__str__()}")


def print_route() -> None:
    # Shows every routing table
    
    for node in NETWORK_GRAPH.nodes:
        if NETWORK_GRAPH.nodes[node]['node_type'] == 'Router':
            routing_table_df = pd.DataFrame(NETWORK_GRAPH.nodes[node]['routing_table'])
            print(f"---------Routers {node} routing table---------\n\n {str(routing_table_df)} \n\n\n")


def find_file(filename: str) -> None:
    """ Checks file exists in current directory"""
    if not os.path.isfile(filename):
        print(f"-File {filename} does not exist in current directory\n")
        exit(0)


def validate_subnets(network_subnets: list) -> None:
    """
    Through subnet validation we make sure that:
        -Every mac address in a subnet is unique
        -Every IP address in a private network is  private
        -Every IP address in a public network is public 
        -Every node in a subnet has the right gateway 
        -Every IP address in a subnet belongs at its subnet
        -Every IP address in a subnet is unique
    """
    for subnet in network_subnets:
       
       # MAC address in a network is unique
        is_unique_mac(subnet)
        
        # IP address in a private network is  private
        if subnet.nat_enabled:
            has_valid_private_addr(subnet)
        
        # IP address in a public network is public 
        else:
            has_valid_public_addr(subnet)

        # IP address in a subnet belongs at its subnet
        ip_belongs_at_subnet(subnet)
        
        # IP address in a subnet is unique
        is_unique_subnet_ip(subnet)


def validate_network() -> None:
    """ Validates the network as a whole"""

    # Checks if linkIDs are unique
    is_unique_linkID()

    # Check if every public IP in the network is unique
    is_unique_network_ip()


def init_visualization(filename: str):
    """This function initializes visualization
        It parses one of the visualization themes from a yaml config file
        and initializes the network renderer

        Available aesthetic profiles:
            -classic_2d_white
            -classic_2d_dark
            -classic_2d_total_black
            -neo_black
    """
    
    vis_prof_opt = "neo_black"

    #Load aesthetic profile config file
    with open("vis_profile_config.yaml", 'r') as cf:		
       
        try:
            vis_theme = yaml.load(cf, Loader = yaml.FullLoader)
        except yaml.YAMLError as exc:
            print(exc)

    
    renderer = rd.Renderer(NETWORK_GRAPH, HELP_NET_GRAPH, vis_theme[vis_prof_opt], filename.split('.')[0])
    renderer.render()
    
#Main funtion
def main(filename: str) -> None:
    
    print('\n')
    
    # Find file in currrent directory
    find_file(filename)    
        
    # Parse the tgf file
    parse_tgf_file(filename)

    init_visualization(filename)
    # Find network subnets
    #network_subnets = find_subnets()
    
    # Validate subnets
    #validate_subnets(network_subnets)
    
    # Validate the whole network
    #validate_network()

    #validate_routing_tables()
    
        
    # Draw network graph
    #render_network(filename.split('.')[0])
    
    # show_network_adapters()
 

if __name__ == "__main__":
    main("test_top.tgf")
    


  
