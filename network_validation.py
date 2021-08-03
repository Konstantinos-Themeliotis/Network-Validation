"""
Network Validation ~Under construction!
    
    -Things TODO now:
        -Routing table
        -Check routing table length

    -Things TODO later:
        -Export to yaml format
    
    -Vizual:
        -Create aesthetic profiles maybe with config files
        -Terminal output decorator 

    -Refactoring:
        -Create an error handling function or class
        -Maybe create an object builder
        -Maybe create some classes and take advantage of software patterns
    
    -Small details TODO:
        -Check if an adapter in a node with same MAC has different IP

"""

#Imports
import networkx as nx
from pyvis.network import Network
import ast
import network_adapter as na
from netaddr import IPNetwork, IPAddress
import os.path
import re
import pandas as pd



# Global variables
# FIXME use only ACCEPTABLE NODE TYPES and rename
NET_VIS_GRAPH = Network(height = '100%', width = '100%', bgcolor = "#222222", font_color = "white")
NETWORK_GRAPH = nx.DiGraph()
PUBLIC_IP_TABLE = pd.DataFrame  #Dataframe with every IP address in the network
ACCEPTABLE_LINK_ATTR = set(('link_ID', 'left_end', 'right_end', 'capacity', 'latency'))
ACCEPTABLE_NODE_ATTR = set(('node_type', 'routing_table'))
ACCEPTABLE_ADAPTER_ATTR = {
    'Client_PC' : set(['MAC', 'IP', 'Mask', 'Gateway', 'DNS']),
    'Server_PC' : set(['MAC', 'IP', 'Mask', 'Gateway', 'DNS']),
    'Router' : set(['MAC', 'IP', 'Mask', 'Gateway', 'DNS', 'NAT', 'private_IP']),
    'Switch' : set(['MAC']),
    'Hub' : set(['msg'])}
ACCEPTABLE_NODE_TYPES = {
    'node_type' : ['Client_PC', 'Server_PC', 'Router', 'Switch', 'Hub'],
    'routing_table' : set(['dest', 'mask', 'link', 'next_hop'])
    }

# TODO Config files for aesthetic profiles
ICONS_MAP = {
        'Client_PC' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/PC.png' , 
        'Server_PC' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/data-server.png' , 
        'Router' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/MyRouter.png' ,
        'Switch' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/Switch%20L2.png' , 
        'Hub' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/myHub2.png'
        }


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
                node  = line.split("~")[0].strip() 
                node_attr = ast.literal_eval(line.split("~")[1].strip())
                
                validate_node_attributes(node,node_attr)
               
                node_tuple = (node, node_attr)
                nodes.append(node_tuple)
                       
            # Parsing edges from file
            else:
                left_end_node = line.split("~")[0].split(" ")[0].strip()
                right_end_node = line.split("~")[0].split(" ")[1].strip()
                link_attr = ast.literal_eval(line.split("~")[1].strip())
                
                validate_edge_attributes(nodes, left_end_node, right_end_node, link_attr)
                
                edge_tuple = (left_end_node, right_end_node, link_attr)
                edges.append(edge_tuple)                         
    
    # Creating Graph
    NETWORK_GRAPH.add_nodes_from(nodes)
    NETWORK_GRAPH.add_edges_from(edges)

   
    # Creating pyvis graph for visualization from networkx object
    NET_VIS_GRAPH.from_nx(NETWORK_GRAPH)


def validate_node_attributes(node: str, node_attr: dict) -> None:
    validate_node_attr_type(node, node_attr)
    #validate_routing_table_attr_value(node, node_attr)  Called from somewhere else


def validate_node_attr_type(node: str, node_attr: dict) -> None: 
    """ Validates if the node has the right attributes"""
    
    invalid_node_attr = set(node_attr) - ACCEPTABLE_NODE_ATTR
    
    if invalid_node_attr:
        print("\n  -Node Attribute Type Error: ")
        print(f"  Attributes {invalide_node_attr} are invalid ({node})\n")
        exit()

    if 'node_type' not in node_attr:
        print("\n  -Node Attribute Type Error: ")
        print(f"  Attribute node_type is missing from node {node}\n")
    
    elif node_attr['node_type'] in ACCEPTABLE_NODE_TYPES['node_type']:
        if node_attr['node_type'] == "Router":
            if 'routing_table' not in node_attr:
                print("\n  -Node Attribute Type Error: ")
                print(f"  Attribute routing_table is missing from node ({node})\n")
                exit()
            else:
                validate_routing_table_attr_type(node, node_attr)
                validate_routing_table_attr_value(node, node_attr)

    else:
        print("Invalid type\n")
        exit()


# TODO: comments
def validate_routing_table_attr_type(node: str, node_attr: dict) -> None:
    # Validates if the routing table has the right attribues
    
    missing_table_attr = ACCEPTABLE_NODE_TYPES['routing_table'] - set(node_attr['routing_table'])
    invalid_table_attr = set(node_attr['routing_table']) - ACCEPTABLE_NODE_TYPES['routing_table']
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
def validate_routing_table_attr_value(node: str, node_attr: dict) -> None:
    """ Validates if routing tables attribute values are correct"""
    
    dest_count =  len(node_attr['routing_table']['dest'])
    mask_count = len(node_attr['routing_table']['mask'])
    link_count = len( node_attr['routing_table']['link'])
    next_hop_count =  len(node_attr['routing_table']['next_hop'])
    
    # Routing table attributes must be of the same length
    if not(dest_count == mask_count == link_count == next_hop_count):
        print(f"-Routing table at {node} is missing some values\n")

    # Destination
    for dest in node_attr['routing_table']['dest']:
        if not is_valid_ip(dest):
            print("  -Routing Table Value Error")
            print(f'{node} has destination invalid value\n')
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
            print(f"  Invalid link ID value at routing table at {node})\n")
            exit()
    
    # Next Hop
    for hop in node_attr['routing_table']['next_hop']:
        if not is_valid_ip(hop):
            print("  -Routing Table Value Error")
            print(f'  {node} has next hop invalid value\n')
            exit()


def validate_edge_attributes(nodes: list, left_end_node: str, right_end_node: str, link_attr: dict) -> None:
    """ Validates the parsed attributes values"""
    
    for node in nodes:
        if node[0] == left_end_node: 
            left_node_type = node[1]['node_type']

        if node[0] == right_end_node:
            right_node_type = node[1]['node_type']
    
    # Global link attributes type validation
    validate_link_attributes_type(link_attr, left_end_node, right_end_node)

    # Global link attributes value validation
    validate_link_attributes_value(link_attr, left_end_node, right_end_node)
    
    # Left-Right End node attributes type validation
    validate_end_node_attributes_type(left_end_node, right_end_node, left_node_type,'left_end', link_attr)
    validate_end_node_attributes_type(right_end_node, left_end_node, right_node_type,'right_end', link_attr)

    # Left-Right End node attributes value validation
    validate_end_node_attributes_value(left_end_node, right_end_node, left_node_type, 'left_end', link_attr)
    validate_end_node_attributes_value(right_end_node, left_end_node, right_node_type, 'right_end', link_attr)


def validate_link_attributes_type(link_attr: dict, from_node: str, to_node: str) -> None:
    """ Validates if the link has the right attributes
      - A = ACCEPTABLE_LINK_ATTR -> Attributes set a link must have
      - B = link_attr -> The parsed attribute set
      - A-B = missing_attr_set -> The set of attributes that are missing from the link
      - B-A = invalid_attr_set -> The set of attributes that should not exist on the link
    """

    missing_attr_set = ACCEPTABLE_LINK_ATTR - set(link_attr)    
    invalid_attr_set = set(link_attr) - ACCEPTABLE_LINK_ATTR
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
def validate_link_attributes_value(link_attr: dict, from_node: str, to_node: str) -> None:
    """ Validates if links attributes have the right values"""
    
    # Link ID value validation
    if link_attr['link_ID'].isdecimal():
        if int(link_attr['link_ID']) <= 0:
            print("\n  -Edge Attribute Value Error: ")
            print(f"  Invalid link ID value at edge ({from_node + ' ' + to_node})\n")
            exit(0)
    else:
        print("\n -Edge Attribute Value Error: ")
        print(f"  Invalid link ID value at edge ({from_node + ' ' + to_node}) -Must be an integer, greater than 0\n")
        exit(0)
    
    # Capacity value validation
    if link_attr['capacity'].isdecimal():
        if int(link_attr['link_ID']) <= 0:
            print("\n  -Edge Attribute Value Error: ")
            print(f"  Invalid link ID value at edge ({from_node + ' ' + to_node})\n")
            exit(0)
    else:
        print("\n  -Edge Attribute Value Error: ")
        print(f"  Invalid capacity value at edge ({from_node + ' ' + to_node}) -Must be an integer, greater than 0\n")
        exit(0)

    # Latency value validation
    if link_attr['latency'].isdecimal():
        if int(link_attr['link_ID']) <= 0:
            print("\n  -Edge Attribute Value Error: ")
            print(f"  Invalid link ID value at edge ({from_node + ' ' + to_node})\n")
            exit(0)
    else:
        print("\n  -Edge Attribute Value Error: ")
        print(f"  Invalid latency value at edge ({from_node + ' ' + to_node}) -Must be an integer,greater than 0\n")
        exit(0)


def validate_end_node_attributes_type(from_node: str, to_node: str, node_type: str, end_node: str, link_attr: dict) -> None:
    """ Validates if the adapter has the right attributes"""
    
    if end_node == 'right_end':
        from_node, to_node = to_node, from_node

    # End node attr eg MAC,IP etc etc
    valid_adapter_attr_set = ACCEPTABLE_ADAPTER_ATTR[node_type] - set(link_attr[end_node])
    invalid_adapter_attr_set = set(link_attr[end_node]) - ACCEPTABLE_ADAPTER_ATTR[node_type]
    found_invalid_adapter_attr = False
    
    if valid_adapter_attr_set:
        found_invalid_adapter_attr = True
        print("\n  -Edge Attribute Type Error: ")
        print(f"  Attributes {valid_adapter_attr_set} are missing from : {from_node}, at edge ({from_node + ' ' + to_node}), with link ID: {link_attr['link_ID']}\n")
            
    if invalid_adapter_attr_set:
        found_invalid_adapter_attr = True
        print("\n  -Edge Attribute Type Error: ")
        print(f"  Attributes {invalid_adapter_attr_set} should not exist at: {from_node} ,at edge  ({from_node + ' ' + to_node}), with link ID: {link_attr['link_ID']}\n")
    
    if found_invalid_adapter_attr:
        exit(0)


def validate_end_node_attributes_value(from_node: str, to_node: str, node_type: str, end_node: str, link_attr: dict) -> None:
    """ Validates if the adapters attributes have the right value """
    
    if end_node == 'right_end':
        from_node, to_node = to_node, from_node

    # Attribute value validation
    if node_type == "Switch":

        if not is_valid_mac(link_attr[end_node]['MAC']):
            print("\n  -Edge Attribute Value Error: ")
            print(f"  MAC addresss  at {from_node}, at edge ({from_node + ' ' + to_node})mac not an acceptable value\n")

    elif node_type in {"Client_PC", "Server_PC", 'Router'}:

        if not is_valid_mac(link_attr[end_node]['MAC']):
            print("\n  -Edge Attribute Value Error: ")
            print(f"  MAC addresss  at {from_node}, at edge ({from_node + ' ' + to_node})mac not an acceptable value\n")
            exit(0)

        if not is_valid_ip(link_attr[end_node]['IP']): 
            print("\n  -Edge Attribute Value Error: ")
            print(f"IP addresss  at {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value\n")
            exit(0)

        if not is_valid_mask(link_attr[end_node]['Mask'] or not is_valid_ip(link_attr[end_node]['Mask'])):
            print("\n  -Edge Attribute Value Error: ")
            print(f"Network Mask at {from_node}, at edge ({from_node + ' ' + to_node}) is not a valid Network Mask\n")
            exit(0)

        if not is_valid_ip(link_attr[end_node]['Gateway']):
            print("\n  -Edge Attribute Value Error: ")
            print(f"  Gateway's address at {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value\n")
            exit(0)

        if not is_valid_ip(link_attr[end_node]['DNS']):
            print("\n  -Edge Attribute Value Error: ")
            print(f"  DNS's addresss  at {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value\n")
            exit(0)

        if node_type == 'Router':
            if not is_valid_nat_opt(link_attr[end_node]['NAT']):
                print("\n  -Edge Attribute Value Error: ")
                print(f"  NAT's value  at {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value\n")
                exit(0)
            if not  is_valid_ip(link_attr[end_node]['private_IP']):
                print("\n  -Edge Attribute Value Error: ")
                print(f"  private_IP value at {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value\n")
                exit(0)


def is_valid_mac(mac: str) -> bool:
    """ Checks if an address is a valid MAC address """
    # TODO Regex to be explained
    return bool(re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()))


def is_valid_ip(ip: str) -> bool:
    """ Checks if an address is a valid IP address """
    
    addr = ip.split(".")
    if len(addr) != 4 or not all((x.isdecimal()) for x in addr) :
        return False    
    
    return all((int(x) >= 0 and int(x) <= 255 and (len(x.lstrip('0')) == len(x) or len(x) == 1)) for x in addr)


def is_valid_mask(mask: str) -> bool: 
    """ Checks if an address is a valid network Mask """
    
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
    """ Checks if nat option in valid """
    return NAT in {'enabled', 'disabled'}
    

# FIXME -To long, repeated code, not elegant
def create_adapters() -> None:
    """ Creates the Adapter ojects from network_adapters """

    # Adding network_adapters attribute to graph
    for node in NETWORK_GRAPH.nodes: 
        NETWORK_GRAPH.nodes[node]["network_adapters"] = []


    # Creating network Adapter object for every different network adapter and adding the Adapter to the node it belongs as attribute
    for edge in NETWORK_GRAPH.edges: 

        left_node_type = NETWORK_GRAPH.nodes[edge[0]]['node_type']
        right_node_type = NETWORK_GRAPH.nodes[edge[1]]['node_type']

        # Left end adapters
        if left_node_type == 'Hub':
            pass
        
        elif left_node_type == 'Router':
            left_end_adapter = na.RouterAdapter(
                                NETWORK_GRAPH.edges[edge]['left_end']["MAC"], NETWORK_GRAPH.edges[edge]['left_end']["IP"], 
                                NETWORK_GRAPH.edges[edge]['left_end']["Mask"], NETWORK_GRAPH.edges[edge]['left_end']["Gateway"], 
                                NETWORK_GRAPH.edges[edge]['left_end']["DNS"], NETWORK_GRAPH.edges[edge]['left_end']["NAT"],  
                                NETWORK_GRAPH.edges[edge]['left_end']["private_IP"])
        
        elif left_node_type == 'Switch':
            left_end_adapter = na.Adapter(
                                NETWORK_GRAPH.edges[edge]['left_end']["MAC"])

        else:
            left_end_adapter = na.PCAdapter(
                                NETWORK_GRAPH.edges[edge]['left_end']["MAC"], NETWORK_GRAPH.edges[edge]['left_end']["IP"], 
                                NETWORK_GRAPH.edges[edge]['left_end']["Mask"],NETWORK_GRAPH.edges[edge]['left_end']["Gateway"], 
                                NETWORK_GRAPH.edges[edge]['left_end']["DNS"])
       
       # Right end adapters
        if right_node_type == 'Hub':
            pass
        
        elif right_node_type == 'Router':
            right_end_adapter = na.RouterAdapter(
                                NETWORK_GRAPH.edges[edge]['right_end']["MAC"], NETWORK_GRAPH.edges[edge]['right_end']["IP"], 
                                NETWORK_GRAPH.edges[edge]['right_end']["Mask"], NETWORK_GRAPH.edges[edge]['right_end']["Gateway"], 
                                NETWORK_GRAPH.edges[edge]['right_end']["DNS"], NETWORK_GRAPH.edges[edge]['right_end']["NAT"], 
                                NETWORK_GRAPH.edges[edge]['right_end']["private_IP"])

        elif right_node_type == 'Switch':
            right_end_adapter = na.Adapter(
                                NETWORK_GRAPH.edges[edge]['right_end']["MAC"])

        else:
            right_end_adapter = na.PCAdapter(
                                NETWORK_GRAPH.edges[edge]['right_end']["MAC"], NETWORK_GRAPH.edges[edge]['right_end']["IP"], 
                                NETWORK_GRAPH.edges[edge]['right_end']["Mask"], NETWORK_GRAPH.edges[edge]['right_end']["Gateway"], 
                                NETWORK_GRAPH.edges[edge]['right_end']["DNS"])


        found_left_adapter = False
        found_right_adapter = False

        if left_node_type == 'Hub': 
            pass
        elif not NETWORK_GRAPH.nodes[edge[0]]['network_adapters']:
            NETWORK_GRAPH.nodes[edge[0]]['network_adapters'].append(left_end_adapter)
        else:
            for adapter in NETWORK_GRAPH.nodes[edge[0]]['network_adapters']:
                if adapter == left_end_adapter: 
                    found_left_adapter = True
            if not found_left_adapter: 
                NETWORK_GRAPH.nodes[edge[0]]['network_adapters'].append(left_end_adapter)

        if right_node_type == 'Hub':
            pass
        elif not NETWORK_GRAPH.nodes[edge[1]]['network_adapters']: 
            NETWORK_GRAPH.nodes[edge[1]]['network_adapters'].append(right_end_adapter)
        else:
            for adapter in NETWORK_GRAPH.nodes[edge[1]]['network_adapters']:
                if adapter == right_end_adapter: 
                    found_right_adapter = True
            if not found_right_adapter: 
                NETWORK_GRAPH.nodes[edge[1]]['network_adapters'].append(right_end_adapter)


def create_subnet_mac_table(subnet: nx.DiGraph) -> pd.DataFrame:
    """ Create a table for every MAC address there is in a given subnet """
    
    mac_table_dict = {"Node": [], "MAC": []}
    for node in subnet:
        if subnet.nodes[node]['node_type'] != "Hub":
            for adapter in subnet.nodes[node]['network_adapters']:
                mac_table_dict["Node"].append(node)
                mac_table_dict["MAC"].append(str(adapter.MAC))

    return pd.DataFrame(mac_table_dict)


def create_network_ip_table() -> pd.DataFrame:
    """ Table that contains every public IP on the network
    
    -Solution1 : Scan the whole NETWORK_GRAPH and add every public ip to the table
    -Solution2 : Add every public subnets ip table to the table
        -Must find Router subnets to contain every network adapter
    
    TODO: Decide beetween solutions. Solution 2 seems to be better
    """
    ip_table_dict = {"Node": [], "IP": []}

    for node in NETWORK_GRAPH:
        for adapter in NETWORK_GRAPH.nodes[node]['network_adapters']:
            if not adapter.IP.is_private():
                ip_table_dict["Node"].append(node)
                ip_table_dict["IP"].append(str(adapter.IP))
    
    NETWORK_GRAPH.ip_table = pd.DataFrame(ip_table_dict)


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


def create_routing_tables() -> pd.DataFrame:
    """Create routing table DataFrames"""
    routing_table_list = []
    routing_table_dict = {"Node": '', "routing_table": ''}
    for node in NETWORK_GRAPH.nodes:
        if NETWORK_GRAPH.nodes[node]['node_type'] == 'Router':
            routing_table_df = pd.DataFrame(NETWORK_GRAPH.nodes[node]['routing_table'])


def draw_network(filename: str) -> None: 
    # Network graph visualization   
    for node in NETWORK_GRAPH.nodes:
        if NETWORK_GRAPH.nodes[node]['node_type'] == 'Router':
            routing_table_df = pd.DataFrame(NETWORK_GRAPH.nodes[node]['routing_table'])
    # Node attributes for visualization 
    for node in NET_VIS_GRAPH.nodes:

        if node['node_type'] == 'Client PC':
            node["size"] = 28
        elif node['node_type'] == 'Switch' or node['node_type'] == 'Hub' :
            node['size'] = 20
        else:
            node['size'] = 20      
        
        node['label'] = f"-{node['label']}-"
        for i in range(len( NETWORK_GRAPH.nodes[node['id']]['network_adapters'])):
            if node['node_type'] != 'Switch' and node['node_type'] != 'Hub' :
                node['label'] += "\n" + str(NETWORK_GRAPH.nodes[node['id']]['network_adapters'][i].IP) 
    
        # Viewed when mouse is over the node
        node['shape'] = 'image'
        node['image'] = ICONS_MAP[node['node_type']]
        node['title'] = node['node_type'] + ' : ' + node['id'] + "<br>" 
        if node['node_type'] == 'Router':
            node['title'] += "Routing Table <br>"
            node['title'] += "dest____mask_________link___nexthop:<br>"
            for index, row in routing_table_df.iterrows():
                node['title'] += str(row['dest']) + "  |  " + str(row['mask']) + "  |   " + str(row['link']) + "  |  " + str(row['next_hop'] +"<br>") 
    
     
    # Edge attributes for visualization - Viewed when mouse is over the link     
    for index, edge in enumerate(NET_VIS_GRAPH.edges):
        
        for node in NET_VIS_GRAPH.nodes:
            if node['id'] == edge['from']:
                left_end = node['node_type'] + " " + node['id']
            if node['id'] == edge['to']:
                right_end = node['node_type'] + " " + node['id']
            
        
        # Link attributes
        edge["title"] = "Link Attributes : <br>  <br> "
        edge["title"] += f"Link ID : {edge['link_ID']}  <br> " 
        edge["title"] += f"Capacity : {edge['capacity']} Mbps  <br>  Latency : {edge['latency']} ms  <br> <br>"
        
        # Left end attributes
        left_end_node_type = NETWORK_GRAPH.nodes[edge['from']]['node_type']
        edge["title"] += f"---Left End :{left_end}  --- <br> "
        
        if left_end_node_type != 'Hub':    
            edge['title'] += f"MAC : {edge['left_end']['MAC']}  <br> "
            if left_end_node_type != 'Switch':
                edge['title'] += f"IP :  {edge['left_end']['IP']} <br> "
                edge['title'] += f"Mask : {edge['left_end']['Mask']} <br> "
                edge['title'] += f"Gateway : {edge['left_end']['Gateway']} <br> "
                edge['title'] += f"DNS : {edge['left_end']['DNS']} <br>"
                if left_end_node_type == 'Router':
                    edge['title'] += f"NAT : {edge['left_end']['NAT']} <br>"
        else:
            edge['title'] += "I am a Hub, I am kinda dump" 

        edge['title'] += "<br>"           
        right_end_node_type = NETWORK_GRAPH.nodes[edge['to']]['node_type']
        
        # Right end attributes 
        edge["title"] += f"---Right End :  {right_end}--- <br> "
        if right_end_node_type != 'Hub':
            edge['title'] += f"MAC : {edge['right_end']['MAC']} <br> "
            if right_end_node_type != 'Switch' :
                edge['title'] += f"IP :  {edge['right_end']['IP']} <br> "
                edge['title'] += f"Mask : {edge['right_end']['Mask']} <br> "    
                edge['title'] += f"Gateway : {edge['right_end']['Gateway']} <br> "
                edge['title'] += f"DNS : {edge['right_end']['DNS']} <br>"
                if right_end_node_type == 'Router':
                    edge['title'] += f"NAT : {edge['right_end']['NAT']} <br>"
        else:
            edge['title'] += "I am a Hub, I am kinda dump <br> No attributes for me"
        
        edge['title'] += "<br>"
 
        
        # Edge attributes - Viewed on edge
        # edge["label"] = f"{edge['capacity']}Mbps"
               

    # Some initial options and display
    # NET_VIS_GRAPH.set_edge_smooth('discrete')
    NET_VIS_GRAPH.toggle_physics(False)
    NET_VIS_GRAPH.barnes_hut()   
    # NET_VIS_GRAPH.force_atlas_2based()
    NET_VIS_GRAPH.show(filename + '_visualization.html')


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


                    subnet.add_nodes_from([(router, {'node_type' : 'Router', 'network_adapters' : router_adapter})])
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

                    subnet.add_nodes_from([(router, {'node_type' : 'Router', 'network_adapters' : router_adapter})])
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
    #  1.Validate destination: Make sure that destination exists in the network
    #  2.Validate link: Make sure that the link/interface exists
    #  3.Validate next_hop : Make sure that next_hop/gateway exists in the network
    
    routing_dest_exists()
    routing_link_exists()
    routing_next_hop_exists()
     pass


def routing_dest_exists(routing_table):
    for dest in routing_table['dest'].values:
        pass


# def validate_routing_link():
#     pass


# def validate_routing_next_hop():
#     pass


def ip_config() -> None: 
    # Shows every adapter
    
    for node in NETWORK_GRAPH.nodes:
        for i in range(len(NETWORK_GRAPH.nodes[node]['network_adapters'])) :
            print(f"Node: {node}, Type: {NETWORK_GRAPH.nodes[node]['node_type']} - Network Adapters: \n{NETWORK_GRAPH.nodes[node]['network_adapters'][i].__str__()}")


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
    Checks if:
        -Every mac address in a network is unique
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
    create_network_ip_table()

    # Checks if linkIDs are unique
    is_unique_linkID()

    # Check if every public IP in the network is unique
    is_unique_network_ip()


#Main funtion
def main(filename: str) -> None:
    
    print('\n')
    
    # Find file in currrent directory
    find_file(filename)    
        
    # Parse the tgf file
    parse_tgf_file(filename)

    # Find network adapters from edge attributes
    create_adapters()

    # Find network subnets
    network_subnets = find_subnets()
    
    # Validate subnets
    validate_subnets(network_subnets)
    
    # Validate the whole network
    validate_network()
        
    # Draw network graph
    # draw_network(filename.split('.')[0])
    
    # show_network_adapters()

   
if __name__ == "__main__":
    main("test_top.tgf")
    


  
