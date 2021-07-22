"""
Network Validation ~Under construction!
    
    -Things TODO now:
        -Add routing tables at Routers attributes-not in the edges

    -Things TODO later:
        -Export to yaml format
    
    -Vizual:
        -Create aesthetic profiles maybe with config files
        -Pop up error in visualization if ie a node does not have the right IP
        -Terminal output decorator 

    -Refactoring:
        -Create an error handling function or class
        -Maybe create an object builder
        -Expand node validation
        -Refactor validate_MAC_address & validate_IP_address functions for loop
    
    -Small details TODO:
        -Validate capacity and latency values
        -Check if an adapter in a node with same MAC has different IP
        -Aesthetic details in help function show_adapters() to show attrs like ipconfig in windows

"""


import networkx as nx
from pyvis.network import Network
import ast
import network_adapter as na
from netaddr import IPNetwork, IPAddress
import os.path
import re



#Global variables
G = nx.DiGraph()
G2 = Network(height = '100%', width = '100%', bgcolor = "#222222", font_color = "white")
acceptable_link_attr = set(('link_ID', 'left_end', 'right_end', 'capacity', 'latency'))
acceptable_node_attr = set(('node_type', 'routing_table'))
acceptable_adapter_attr = {
    'Client_PC' : set(['MAC', 'IP', 'Mask', 'Gateway', 'DNS']),
    'Server_PC' : set(['MAC', 'IP', 'Mask', 'Gateway', 'DNS']),
    'Router' : set(['MAC', 'IP', 'Mask', 'Gateway', 'DNS', 'NAT', 'private_IP']),
    'Switch' : set(['MAC']),
    'Hub' : set(['msg'])
}

#Acceptable node type attributes and acceptable node attribute values
acceptable_node_types = {
    'node_type' : ['Client_PC', 'Server_PC', 'Router', 'Switch', 'Hub']
    }

#The icon map for different node types used for vizualization, icons are stored in my Github account
icons_map = {
        'Client_PC' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/PC.png' , 
        'Server_PC' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/data-server.png' , 
        'Router' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/MyRouter.png' ,
        'Switch' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/Switch%20L2.png' , 
        'Hub' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/myHub2.png'
        }

#Parses the .tgf file
def parse_tgf_file(filename):
    
    nodes_parsing_completed = False
    nodes = []
    edges = []

    with open(filename) as f:
        while True:    
            
            #Reading the file line-line
            line = f.readline()

            #End of file
            if not line or line.isspace():
                break
            
            #Nodes from  edges seperator in tgf file
            if "#" in line: 
                nodes_parsing_completed = True
                continue

            #Parsing nodes from file      
            if not nodes_parsing_completed: 
                node  = line.split("~")[0].strip() 
                node_attr = ast.literal_eval(line.split("~")[1].strip())
                
                validate_node_attributes(node,node_attr)
               
                node_tuple = (node, node_attr)
                nodes.append(node_tuple)
                       
            #Parsing edges from file
            else:
                left_end_node = line.split("~")[0].split(" ")[0].strip()
                right_end_node = line.split("~")[0].split(" ")[1].strip()
                link_attr = ast.literal_eval(line.split("~")[1].strip())
                
                validate_edge_attributes(nodes, left_end_node, right_end_node, link_attr)
                
                #print(f'Left node type {type(left_end_node)}, right node type {type(right_end_node)}, attr type {type(link_attr)} ')
                edge_tuple = (left_end_node, right_end_node, link_attr)
                edges.append(edge_tuple)                         
    
    #Creating Graph
    G.add_nodes_from(nodes)
    G.add_edges_from(edges)

   
    #Creating pyvis graph for visualization from networkx object
    G2.from_nx(G)


#TODO -expand validation for routing table and attributes(not only values)
def validate_node_attributes(node, node_attr):
    
    #Validation check for node attributes-values
    for attr_value in list(node_attr):
        if attr_value in acceptable_node_types: 
            if node_attr[attr_value] not in acceptable_node_types[attr_value]: 
                print(f"Not acceptable  {attr_value} value at node: {node}")
                exit()
        else: 
            print(f"{attr_value} is not an acceptable attribute at node: {node}")
            exit()


#Validates the parsed attributes values
def validate_edge_attributes(nodes, left_end_node, right_end_node, link_attr):
    
    for node in nodes:
        if node[0] == left_end_node: 
            left_node_type = node[1]['node_type']

        if node[0] == right_end_node:
            right_node_type = node[1]['node_type']
    
    #Global link attributes type validation
    validate_link_attributes_type(link_attr, left_end_node, right_end_node)

    #Global link attributes value validation
    validate_link_attributes_value(link_attr, left_end_node, right_end_node)
    
    #Left-Right End node attributes type validation
    validate_end_node_attributes_type(left_end_node, right_end_node, left_node_type,'left_end', link_attr)
    validate_end_node_attributes_type(right_end_node, left_end_node, right_node_type,'right_end', link_attr)

    #Left-Right End node attributes value validation
    validate_end_node_attributes_value(left_end_node, right_end_node, left_node_type, 'left_end', link_attr)
    validate_end_node_attributes_value(right_end_node, left_end_node, right_node_type, 'right_end', link_attr)


def validate_link_attributes_type(link_attr, from_node, to_node):
    # A = acceptable_link_attr -> The attribute set a link must have
    # B = link_attr -> The parsed attribute set
    # A-B -> The set of attributes that are missing from the link
    # B-A -> The set of attributes that should not exist on the link
    
    missing_attr_set = acceptable_link_attr.difference(set(link_attr))    
    invalid_attr_set = set(link_attr).difference(acceptable_link_attr)
    found_invalid_parsed_attr = False

    if missing_attr_set:
        print(f"Attributes {missing_attr_set} are missing from edge ({from_node + ' ' + to_node})")
        found_invalid_parsed_attr = True

    if invalid_attr_set:
        print(f"Attributes {invalid_attr_set} are invalid or misspelled at edge ({from_node + ' ' + to_node})")
        found_invalid_parsed_attr = True
        
    if found_invalid_parsed_attr:
        exit(0)


def validate_link_attributes_value(link_attr, from_node, to_node):
    #Link ID value validation
    if link_attr['link_ID'].isdecimal():
        if int(link_attr['link_ID']) <= 0:
            print(f"Invalid link ID value at edge ({from_node + ' ' + to_node})")
            exit(0)
    else:
        print(f"Invalid link ID value at edge ({from_node + ' ' + to_node}) -Must be an integer, greater than 0")
        exit(0)
    
    #Capacity value validation
    if link_attr['capacity'].isdecimal():
        if int(link_attr['link_ID']) <= 0:
            print(f"Invalid link ID value at edge ({from_node + ' ' + to_node})")
            exit(0)
    else:
        print(f"Invalid capacity value at edge ({from_node + ' ' + to_node}) -Must be an integer, greater than 0")
        exit(0)

    #Latency value validation
    if link_attr['latency'].isdecimal():
        if int(link_attr['link_ID']) <= 0:
            print(f"Invalid link ID value at edge ({from_node + ' ' + to_node})")
            exit(0)
    else:
        print(f"Invalid latency value at edge ({from_node + ' ' + to_node}) -Must be an integer,greater than 0")
        exit(0)



def validate_end_node_attributes_type(from_node, to_node, node_type, end_node, link_attr):
    if end_node == 'right_end':
        from_node, to_node = to_node, from_node

    #End node attr eg MAC,IP etc etc
    valid_adapter_attr_set = acceptable_adapter_attr[node_type].difference(set(link_attr[end_node]))
    invalid_adapter_attr_set = set(link_attr[end_node]).difference(acceptable_adapter_attr[node_type])
    found_invalid_adapter_attr = False
    
    if valid_adapter_attr_set:
        found_invalid_adapter_attr = True
        print(f"Parsing Error: Attributes {valid_adapter_attr_set} are missing from node: {from_node}, at edge ({from_node + ' ' + to_node}), with link ID: {link_attr['link_ID']}")
            
    if invalid_adapter_attr_set:
        found_invalid_adapter_attr = True
        print(f"Parsing Error: Attributes {invalid_adapter_attr_set} should not exist at node: {from_node} ,at edge  ({from_node + ' ' + to_node}), with link ID: {link_attr['link_ID']}")
    
    if found_invalid_adapter_attr:
        exit(0)


def validate_end_node_attributes_value(from_node, to_node,  node_type, end_node, link_attr):
    
    if end_node == 'right_end':
        from_node, to_node = to_node, from_node
    
    #Attribute value validation
    if node_type == "Switch":
        if not is_valid_MAC(link_attr[end_node]['MAC']):
            print(f"Attribute Value Error: MAC addresss  at node {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value ")

    elif node_type in ["Client_PC", "Server_PC", 'Router']:
        if not is_valid_MAC(link_attr[end_node]['MAC']):
            print(f"Attribute Value Error: MAC addresss  at node {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value ")
            exit(0)
        if not is_valid_IP(link_attr[end_node]['IP']): 
            print(f"Attribute Value Error: IP addresss  at node {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value ")
            exit(0)
        if not is_valid_Mask(link_attr[end_node]['Mask'] or not is_valid_IP(link_attr[end_node]['Mask'])):
            print(f"Attribute Value Error: Network Mask at node {from_node}, at edge ({from_node + ' ' + to_node}) is not a valid Network Mask ")
            exit(0)
        if not is_valid_IP(link_attr[end_node]['Gateway']):
            print(f"Attribute Value Error: Gateway's address at node {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value ")
            exit(0)
        if not is_valid_IP(link_attr[end_node]['DNS']):
            print(f"Attribute Value Error: DNS's addresss  at node {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value ")
            exit(0)
        if node_type == 'Router':
            if not is_valid_NAT(link_attr[end_node]['NAT']):
                print(f"Attribute Value Error: NAT's value  at node {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value ")
                exit(0)
            if not  is_valid_IP(link_attr[end_node]['private_IP']):
                print(f"Attribute Value Error: private_IP value at node {from_node}, at edge ({from_node + ' ' + to_node}) is not an acceptable value")
                exit(0)

#TODO Regex to be explained
def is_valid_MAC(MAC):
    return bool(re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", MAC.lower()))


def is_valid_IP(IP):
    addr = IP.split(".")
    if len(addr) != 4 or not all((x.isdecimal()) for x in addr) :
        return False    
    
    return all((int(x) >= 0 and int(x) <= 255 and (len(x.lstrip('0')) == len(x) or len(x) == 1)) for x in addr)
        

def is_valid_Mask(Mask):
    addr = Mask.split(".")
    if not all((x.isdecimal()) for x in addr):
        return False
    
    for index, st in enumerate(addr):
        #Transform integer to 8bit binary
        addr[index] = f'{int(addr[index]):08b}'
    
    binary_mask = "".join(addr)
    ones_counter = 0 
    for bit in binary_mask:
        if bit == '1':
            ones_counter +=1
        else:
            break
    
    return(binary_mask.count('1') == ones_counter)

def is_valid_NAT(NAT):
    return NAT in ['enabled', 'disabled']
    

#FIXME -To long for function and maybe redundant code
#Creates the Adapter ojects from network_adapters
def create_adapters():

    #Adding network_adapters attribute to graph
    for node in G.nodes: 
        G.nodes[node]["network_adapters"] = []


    #Creating network Adapter object for every different network adapter and adding the Adapter to the node it belongs as attribute
    for edge in G.edges: 

        left_node_type = G.nodes[edge[0]]['node_type']
        right_node_type = G.nodes[edge[1]]['node_type']

        #Left end adapters
        if left_node_type == 'Hub':
            pass
        
        elif left_node_type == 'Router':
            left_end_adapter = na.RouterAdapter(
                                G.edges[edge]['left_end']["MAC"], G.edges[edge]['left_end']["IP"], 
                                G.edges[edge]['left_end']["Mask"], G.edges[edge]['left_end']["Gateway"], 
                                G.edges[edge]['left_end']["DNS"], G.edges[edge]['left_end']["NAT"],  
                                G.edges[edge]['left_end']["private_IP"])
        
        elif left_node_type == 'Switch':
            left_end_adapter = na.Adapter(
                                G.edges[edge]['left_end']["MAC"])

        else:
            left_end_adapter = na.PCAdapter(
                                G.edges[edge]['left_end']["MAC"], G.edges[edge]['left_end']["IP"], 
                                G.edges[edge]['left_end']["Mask"],G.edges[edge]['left_end']["Gateway"], 
                                G.edges[edge]['left_end']["DNS"])
       
       #Right end adapters
        if right_node_type == 'Hub':
            pass
        
        elif right_node_type == 'Router':
            right_end_adapter = na.RouterAdapter(
                                G.edges[edge]['right_end']["MAC"], G.edges[edge]['right_end']["IP"], 
                                G.edges[edge]['right_end']["Mask"], G.edges[edge]['right_end']["Gateway"], 
                                G.edges[edge]['right_end']["DNS"], G.edges[edge]['right_end']["NAT"], 
                                G.edges[edge]['right_end']["private_IP"])

        elif right_node_type == 'Switch':
            right_end_adapter = na.Adapter(
                                G.edges[edge]['right_end']["MAC"])

        else:
            right_end_adapter = na.PCAdapter(
                                G.edges[edge]['right_end']["MAC"], G.edges[edge]['right_end']["IP"], 
                                G.edges[edge]['right_end']["Mask"], G.edges[edge]['right_end']["Gateway"], 
                                G.edges[edge]['right_end']["DNS"])


        found_left_adapter = False
        found_right_adapter = False

        if left_node_type == 'Hub': 
            pass
        elif not G.nodes[edge[0]]['network_adapters']:
            G.nodes[edge[0]]['network_adapters'].append(left_end_adapter)
        else:
            for adapter in G.nodes[edge[0]]['network_adapters']:
                if adapter == left_end_adapter: 
                    found_left_adapter = True
            if not found_left_adapter: 
                G.nodes[edge[0]]['network_adapters'].append(left_end_adapter)

        if right_node_type == 'Hub':
            pass
        elif not G.nodes[edge[1]]['network_adapters']: 
            G.nodes[edge[1]]['network_adapters'].append(right_end_adapter)
        else:
            for adapter in G.nodes[edge[1]]['network_adapters']:
                if adapter == right_end_adapter: 
                    found_right_adapter = True
            if not found_right_adapter: 
                G.nodes[edge[1]]['network_adapters'].append(right_end_adapter)



#Network graph visualization   
def draw_network(filename): 

    #Node attributes for visualization 
    for node in G2.nodes:

        #TODO Setting node sizes according to the node type.(Based on icons and the profiles)
        if node['node_type'] == 'Client PC':
            node["size"] = 28
        elif node['node_type'] == 'Switch' or node['node_type'] == 'Hub' :
            node['size'] = 20
        else:
            node['size'] = 20      
        
        #Viewed under the node -TODO Take data from G graph and not G2
        node['label'] = f"-{node['label']}-"
        for i in range(len( G.nodes[node['id']]['network_adapters'])):
            if node['node_type'] != 'Switch' and node['node_type'] != 'Hub' :
                node['label'] += "\n" + G.nodes[node['id']]['network_adapters'][i].IP 
    
        #Viewed when mouse is over the node
        node['title'] = node['node_type'] + ' : ' + node['id'] 
        node['shape'] = 'image'
        node['image'] = icons_map[node['node_type']]
    
     
    #Edge attributes for visualization - Viewed when mouse is over the link     
    for index, edge in enumerate(G2.edges):
        
        for node in G2.nodes:
            if node['id'] == edge['from']:
                left_end = node['node_type'] + " " + node['id']
            if node['id'] == edge['to']:
                right_end = node['node_type'] + " " + node['id']
            
        
        #Link attributes
        edge["title"] = "Link Attributes : <br>  <br> "
        edge["title"] += f"Link ID : {edge['link_ID']}  <br> " 
        edge["title"] += f"Capacity : {edge['capacity']} Mbps  <br>  Latency : {edge['latency']} ms  <br> <br>"
        
        #Left end attributes
        left_end_node_type = G.nodes[edge['from']]['node_type']
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
        right_end_node_type = G.nodes[edge['to']]['node_type']
        
        #Right end attributes 
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
 
        
        #Edge attributes - Viewed on edge
        #edge["label"] = f"{edge['capacity']}Mbps"
               

    #Some initial options and display
    #G2.set_edge_smooth('discrete')
    G2.toggle_physics(False)
    G2.barnes_hut()   
    #G2.force_atlas_2based()
    G2.show(filename + '_visualization.html')
    


#Finds subnets in a given network - Returns a list of nx graph Objects
def find_subnets():
    
    G3 = G.copy()
    routers=[]
    subnets= []

    #Finds physical subnets by removing routers
    for node in list(G3.nodes): 
        if G3.nodes[node]['node_type'] == 'Router':
            routers.append(node)
            G3.remove_node(node)

    #TODO Maybe use generators or yield to save space
    temp_subnets = [G3.subgraph(n) for n in nx.weakly_connected_components(G3)]

    #Adding the router to the subnet it belongs
    for sub in temp_subnets:
        subnet = sub.copy()
        for node in sub.nodes:
            for router in routers:
                if G.has_edge(node, router):
                    
                    mask = G.edges[node, router]['right_end']["Mask"]
                    nat_enabled = G.edges[node, router]['right_end']["NAT"] == 'enabled'
                    if nat_enabled:
                        gateway =  G.edges[node, router]['right_end']["private_IP"]
                    else : 
                        gateway = G.edges[node, router]['right_end']["IP"]

                    router_adapter = [na.RouterAdapter(
                                G.edges[node, router]['right_end']["MAC"], G.edges[node, router]['right_end']["IP"], 
                                G.edges[node, router]['right_end']["Mask"], G.edges[node, router]['right_end']["Gateway"], 
                                G.edges[node, router]['right_end']["DNS"], G.edges[node, router]['right_end']["NAT"],  
                                G.edges[node, router]['right_end']["private_IP"])]


                    subnet.add_nodes_from([(router, {'node_type' : 'Router', 'network_adapters' : router_adapter})])
                    subnet.add_edges_from([(node, router, G.edges[node, router])])

                if G.has_edge(router, node):
                    
                    mask = G.edges[router, node]['left_end']["Mask"]
                    nat_enabled = G.edges[router, node]['left_end']["NAT"] == 'enabled'
                    if nat_enabled:
                        gateway = G.edges[router, node]['left_end']["private_IP"]
                    else :
                        gateway = G.edges[router, node]['left_end']["IP"]

                    router_adapter = [na.RouterAdapter(
                                G.edges[router, node]['left_end']["MAC"], G.edges[router, node]['left_end']["IP"], 
                                G.edges[router, node]['left_end']["Mask"], G.edges[router, node]['left_end']["Gateway"], 
                                G.edges[router, node]['left_end']["DNS"], G.edges[router, node]['left_end']["NAT"],  
                                G.edges[router, node]['left_end']["private_IP"])]

                    subnet.add_nodes_from([(router, {'node_type' : 'Router', 'network_adapters' : router_adapter})])
                    subnet.add_edges_from([(router, node, G.edges[router, node])])

        if not validate_subnet(subnet):
            print("Found subnet with out router")
            exit(0)

        #Subnets attributes as graph attributes
        subnet.nat_enabled = nat_enabled
        subnet.gateway = gateway
        subnet.mask = mask

        subnets.append(subnet)

    return subnets    

#Checks if every subnet has a router-gateway
def validate_subnet(subnet):
    return any(subnet.nodes[node]['node_type'] == 'Router' for node in subnet)


def is_unique_linkID():
    edge_list = list(G.edges)
    for index, edge in enumerate(G.edges):
        for i in range(index+1, len(edge_list)):
            if G.edges[edge]['link_ID'] == G.edges[edge_list[i]]['link_ID']:
                print(f"Found duplicate link ID at edges {edge}, {edge_list[i]}. Link ID must be unique ")
        



#Validates if a MAC address is unique at its subnet
def is_unique_MAC(network_subnets):

    #for every subnet
    for sub_index, subnet in enumerate(network_subnets):        
        
        #for every node in subnet 
        for index, node in enumerate(subnet):
            node_help_list = list(subnet.nodes)
            
            #for every adapter in node
            for adapter in subnet.nodes[node]['network_adapters']: 
                
                #Checks with every other node
                for node_2 in range(index+1, len(node_help_list)): 
                    
                    #Check with every adapter on the other node
                    for adapter_2 in subnet.nodes[node_help_list[node_2]]['network_adapters']: 
                        if adapter == adapter_2: 
                            print(f"Node: {node}, has the same MAC address as node: {node_help_list[node_2]}")
            
            del node_help_list[0]

#Validates the IP addresses
def validate_IP_network(network_subnets):
    IP_belongs_at_subnet(network_subnets)
    #is_unique_IP(network_subnets)
    

#Checks if IP belongs to its subnet
def IP_belongs_at_subnet(network_subnets):
    for subnet in network_subnets:
        
        if subnet.nat_enabled :
            validate_NAT_address(subnet)
        
        #Find nodes gateway, see if it matches subnets gateway
        #and see if nodes IP belongs at subnet
        for node in subnet:
            if subnet.nodes[node]['node_type'] not in ['Switch', 'Hub', 'Router']:
                for i in range(len(subnet.nodes[node]['network_adapters'])):                    
                    nodes_gateway_address = subnet.nodes[node]['network_adapters'][i].Gateway
                   
                    #Checks if subnets gateway matches the gateway of the rest of the nodes
                    if subnet.gateway != nodes_gateway_address:
                        print(f"Gateway error at node{node}, routers IP: {subnet.gateway} subnet_gateway {nodes_gateway_address}")    
                    
                    ip_address = subnet.nodes[node]['network_adapters'][i].IP
                    subnet_mask = '/' + str(IPAddress(subnet.nodes[node]['network_adapters'][i].Mask).netmask_bits())
                    
                    #IP belongs at its subnet
                    if IPAddress(ip_address) not in IPNetwork(subnet.gateway + subnet_mask):
                        print(f"Node's {node} IP address: {ip_address}  does not belong at its subnet {subnet.gateway + subnet_mask}")         


#FIXME WORST FUNCTION EVER
def is_unique_IP(subnets):
    subnet_help_list = list(subnets)
    for sub_index, subnet in enumerate(subnets):
        node_help_list = list(subnet.nodes)

        if subnet.nat_enabled: 
            #Finds same IP in NAT subnet
            for index, node in enumerate(subnet):
                if subnet.nodes[node]['node_type'] not in ["Switch", "Hub"]:
                    for adapter in subnet.nodes[node]['network_adapters']:
                        for node_2 in range(index+1, len(node_help_list)):
                            if subnet.nodes[node_help_list[node_2]]['node_type'] not in ['Switch', 'Hub']:
                                for adapter_2 in subnet.nodes[node_help_list[node_2]]['network_adapters']: 
                                    if adapter.IP == adapter_2.IP:
                                        print("For all time")

            for s_index in range(sub_index+1, len(subnets)):
                if subnets[sub_index+1].nat_enabled:
                    if subnet.gateway == subnets[sub_index+1].gateway:
                        print("Ta piasame ta lefta mas")
                        continue
                else:
                    for s_node in subnets[s_index]:
                        if subnets[s_index].nodes[s_node]['node_type'] not in ['Switch', 'Hub']:
                            for ada in subnets[s_index].nodes[s_node]['network_adapters']:
                                if subnet.gateway == ada.IP:
                                    print("O kakos xamos o idios")

        else:
            #subnet_help_list = list(subnets)
            for index, node in enumerate(subnet):
                #Find same IP in its own network
                if subnet.nodes[node]['node_type'] not in ["Switch", "Hub"]:
                    for adapter in subnet.nodes[node]['network_adapters']:
                        for node_2 in range(index+1, len(node_help_list)):
                            if subnet.nodes[node_help_list[node_2]]['node_type'] not in ['Switch', 'Hub']:
                                for adapter_2 in subnet.nodes[node_help_list[node_2]]['network_adapters']: 
                                    if adapter.IP == adapter_2.IP:
                                        print("For all time 2 ")

                        #Check again if its NAT
                        for sub_2_index in range(sub_index+1, len(subnets)):
                            if (
                                subnets[sub_2_index].nat_enabled
                                and adapter.IP == subnets[sub_2_index].gateway
                            ):
                                print("For all time 3")
                                continue

                            for sub_node in subnets[sub_2_index]:
                                if subnets[sub_node].nodes['node_type'] not in ["Switch", "Hub"]:
                                    for ad in subnet.nodes[sub_node]['node_type']:
                                        if adapter.IP == ad.IP:
                                            print("For all time 3")







# def is_unique_IP():
#     node_help_list = list(G.nodes)
#     #Checks if an IP address is unique
#     #For every node
#     for index, node in enumerate(G.nodes):
#         if G.nodes[node]['node_type'] not in ['Switch', 'Hub']:
        
#             #For every nodes adapter
#             for adapter in G.nodes[node]['network_adapters']: 
                
#                 #For every other node
#                 for node_2 in range(index+1, len(node_help_list)):
#                     if G.nodes[node_help_list[node_2]]['node_type'] not in ['Switch', 'Hub']:

#                         #Check with every adapter on the other node
#                             for adapter_2 in G.nodes[node_help_list[node_2]]['network_adapters']: 
                                
#                                 if adapter.IP == adapter_2.IP:
#                                     print(f"Node: {node} with IP address: {adapter.IP}, has the same IP address as node: {node_help_list[node_2]} with IP address: {adapter_2.IP}")




def validate_NAT_address(subnet):
    
    # NAT prefixes:
    #     10/8  
    #     172.16/12    
    #     192.168/16

    for node in subnet:
        if subnet.nodes[node]['node_type'] == 'Router':
            NAT_IP = subnet.nodes[node]['network_adapters'][0].private_IP
        elif subnet.nodes[node]['node_type'] in ['Client_PC', 'Server_PC'] :
            NAT_IP = subnet.nodes[node]['network_adapters'][0].IP   
        else :
           continue

        #10/8
        if NAT_IP.split(".")[0] == '10':
            pass
        #178.16/12
        elif NAT_IP.split(".")[0] == '192' and NAT_IP.split(".")[1] == '168':
            pass
        #192.168/16
        elif NAT_IP.split(".")[0] == '172':
            x = NAT_IP.split(".")[1]
            IP_binary = f"{int(x):08b}"
            bits = IP_binary[:int(len(IP_binary)/2)]

            if int(bits, 2) != 1:
                print(f"Nodes {node} IP address {NAT_IP} in not a valid private NAT IP address") 

        else:
            print(f"Nodes {node} IP address {NAT_IP} in not a valid private NAT IP address")        




def validate_routing_tables():
    pass

#Help function that prints every nodes network adapters
def show_network_adapters(): 
    for node in G.nodes:
        for i in range(len(G.nodes[node]['network_adapters'])) :
            print(f"Node: {node}, Type: {G.nodes[node]['node_type']} - Network Adapters: \n {G.nodes[node]['network_adapters'][i].__str__()}")
    

def main(filename):
    
    if not os.path.isfile(filename):
        print(f"File {filename} does not exist in current directory")
        exit(0)
        
    #Parse the tgf file
    parse_tgf_file(filename)

    #Find network adapters from edge attributes
    create_adapters()

    #Validates that every link ID is unique
    is_unique_linkID()
      
    #Find network subnets
    network_subnets = find_subnets()

    
    #Validate MAC addresses
    is_unique_MAC(network_subnets)
    
    #Validate IP addresses
    validate_IP_network(network_subnets)

    
    #Draw network graph
    draw_network(filename.split('.')[0])
    
    #show_network_adapters()


#Main    
if __name__ == "__main__":
    main("test_top.tgf")


  
