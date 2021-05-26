"""
Network Validation ~Under construction!
    
    -Things TODO next:
        -Add NAT flag at attributes, identify a NAT network and validate its IP's
        -Modify Adapter class for different network adapter types - change tgf files attributes-check DNS attribute
        -Add routing tables at Routers attributes-not in the edges
        -Maybe Add Routers to the subnets
        -Maybe add Adapter object as edge attributes  
        -Validate all the edge attributes
        -Check if an adapter in a node with same MAC has different IP
        -Have a look at IP address libraries

    -Things to come later:
        -Export to yaml format
    
    -Vizual:
        -Create aesthetic profiles with config files
"""


import networkx as nx
from pyvis.network import Network
import ast
import network_adapter as na
from netaddr import IPNetwork, IPAddress



#Graph init - Global variables
G = nx.Graph()
G2 = Network(height = '100%', width = '100%', bgcolor = "#222222", font_color = "white")
network_subnets = ''
filename = "topology1-1"


#Acceptable node attributes and acceptable node attribute values
node_acceptable_attr = {
        'node_type' : ['Client PC', 'Server PC', 'Router', 'L2 Switch', 'L3 Switch', 'Hub']
        }

#The icon map for different node types used for vizualization, icons are stored in my Github account
icons_map = {
        'Client PC' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/PC.png' , 
        'Server PC' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/data-server.png' , 
        'Router' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/%CE%A7%CF%89%CF%81%CE%AF%CF%82%20%CF%84%CE%AF%CF%84%CE%BB%CE%BF.png' ,
        'L2 Switch' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/Switch%20L2.png' ,
        'L3 Switch' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/my_switch.png' , 
        'Hub' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/myHub2.png'
        }


#Parses the .tgf file
def parse_tgf_file():
    nodes_parsing_completed = False
    nodes = []
    edges = []

    with open(filename + ".tgf") as f:
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
                
                #Validation check for node attributes-values
                for key in list(node_attr):
                    if key in node_acceptable_attr: 
                        if node_attr[key] in node_acceptable_attr[key]: 
                            node_tuple = (node, node_attr)
                            nodes.append(node_tuple)
                        else: 
                            print(f"Not acceptable  {key} value at node: {node}")
                            exit()
                    else: 
                        print(f"{key} is not an acceptable attribute at node: {node}")
                        exit()
                    
                
            #Parsing edges from file- TODO edge-attribute validation check
            else:
                edge_attr = ast.literal_eval(line.split("~")[1].strip())
                node_1 = line.split("~")[0].split(" ")[0].strip()
                node_2 = line.split("~")[0].split(" ")[1].strip()
                edge_tuple = (node_1, node_2, edge_attr)
                edges.append(edge_tuple)                         
    
    #Creating Graph
    G.add_nodes_from(nodes)
    G.add_edges_from(edges)
   
    #Creating pyvis graph for visualization from networkx object
    G2.from_nx(G)

    #Adding network_adapters attribute to graph
    for node in G.nodes: 
        G.nodes[node]["network_adapters"] = []

    
    #Creating network Adapter object for every different network adapter and adding the Adapter to the node it belongs as attribute
    for edge in edges: 
        #print(f"degub 1 {edge} ")
        left_node_type = G.nodes[edge[0]]['node_type'] 
        right_node_type = G.nodes[edge[1]]['node_type']
        
        #Hub has no network adapter object - It actually has but its L1 adapter.
        if left_node_type != 'Hub':
            #Left end Layer 2 Adapter
            if left_node_type == 'L2 Switch':
                left_end_adapter = na.Adapter(edge[2]['left_end']["MAC"], edge[2]['left_end']["Gateway"])
            #Left end Layer3 Switch Adapter
            elif left_node_type == 'L3 Switch':
                left_end_adapter = na.L3SwitchAdapter(edge[2]['left_end']["MAC"], edge[2]['left_end']["IP"], edge[2]['left_end']["Mask"], edge[2]['left_end']["Gateway"])
            #Left end Router Adapter
            elif left_node_type == 'Router':
                left_end_adapter = na.L3RouterAdapter(edge[2]['left_end']["MAC"], edge[2]['left_end']["IP"], edge[2]['left_end']["Mask"], edge[2]['left_end']["Gateway"], edge[2]['left_end']["NAT"])
            #Client PC or Server PC adapter - They have the same object type
            else :
                #print(f"Debug: {edge[2]['left_end']["MAC"]} | {edge[2]['left_end']["IP"]} | {edge[2]['left_end']["Mask"]} | {edge[2]['left_end']["Gateway"]} | {edge[2]['left_end']["DNS"]}")
                left_end_adapter = na.L7Adapter(edge[2]['left_end']["MAC"], edge[2]['left_end']["IP"], edge[2]['left_end']["Mask"], edge[2]['left_end']["Gateway"], edge[2]['left_end']["DNS"])
        
        if right_node_type != 'Hub':    
            #Right end Layer 2 Adapter
            if right_node_type == 'L2 Switch':
                right_end_adapter = na.Adapter(edge[2]['right_end']["MAC"], edge[2]['right_end']["Gateway"])
            #Right end Layer3 Switch Adapter
            elif right_node_type == 'L3 Switch':
                right_end_adapter = na.L3SwitchAdapter(edge[2]['right_end']["MAC"], edge[2]['right_end']["IP"], edge[2]['right_end']["Mask"], edge[2]['right_end']["Gateway"])
            #Right end Router Adapter
            elif right_node_type == 'Router':
                right_end_adapter = na.L3RouterAdapter(edge[2]['right_end']["MAC"], edge[2]['right_end']["IP"], edge[2]['right_end']["Mask"], edge[2]['right_end']["Gateway"], edge[2]['right_end']["NAT"])
            #Client PC or Server PC adapter - They have the same object type
            else :
                right_end_adapter = na.L7Adapter(edge[2]['right_end']["MAC"], edge[2]['right_end']["IP"], edge[2]['right_end']["Mask"], edge[2]['right_end']["Gateway"], edge[2]['right_end']["DNS"])


        found_left_adapter = False 
        found_right_adapter = False
        
        #Checks if left end adapter already exists
        if left_node_type != 'Hub':
            if not G.nodes[edge[0]]['network_adapters']: 
                G.nodes[edge[0]]['network_adapters'].append(left_end_adapter)
            else:
                for adapter in G.nodes[edge[0]]['network_adapters']:
                    if adapter == left_end_adapter: 
                        found_left_adapter = True

                        '''
                        #Checks if an adapter in a node with same MAC has different IP-TODO
                        if adapter.IP != left_end_adapter.IP :
                            print(f'Found same node adapter with different IP address at node {edge[0]}')
                        '''
                if not found_left_adapter: 
                    G.nodes[edge[0]]['network_adapters'].append(left_end_adapter)
        
        if right_node_type != 'Hub':
            #Checks if right end adapter already exists
            if not G.nodes[edge[1]]['network_adapters']: 
                G.nodes[edge[1]]['network_adapters'].append(right_end_adapter)
            else:
                for adapter in G.nodes[edge[1]]['network_adapters']:
                    if adapter == right_end_adapter: 
                        found_right_adapter = True
                        '''            
                        #Checks if an adapter in a node with same MAC has different IP-TODO
                        if adapter.IP != left_end_adapter.IP :
                            print(f'Found same node adapter with different IP address at node {edge[1]}')
                        '''
                if not found_right_adapter: 
                    G.nodes[edge[1]]['network_adapters'].append(right_end_adapter)

#Graph visualization   

def draw_graph(): 

    #Adding node attributes for visualization 
    for node in G2.nodes:      
        
        #Viewed under the node -TODO Take data from G graph and not G2
        node['label'] = f"-{node['label']}-"
        for i in range(len( G.nodes[node['id']]['network_adapters'])):
            if node['node_type'] != 'L2 Switch' and node['node_type'] != 'Hub' :
                node['label'] += "\n" + G.nodes[node['id']]['network_adapters'][i].IP 
    
        #Viewed when mouse is over the node
        node['title'] = node['node_type'] + ' : ' + node['id'] 
        node['shape'] = 'image'
        node['image'] = icons_map[node['node_type']]
        
        #Setting node sizes according to the node type.(Based on icons)
        if node['node_type'] == 'Client PC':
            node["size"] = 28
        elif node['node_type'] == 'L2 Switch' or node['node_type'] == 'L3 Switch' or node['node_type'] == 'Hub' :
            node['size'] = 20
        else:
            node['size'] = 20
     
    #Adding edge attributes for visualization - Viewed when mouse is over the link     
    for index, edge in enumerate(G2.edges):
        
        '''
        Correcting an error in pyvis library where it swaps the edges and their attributes
        in Graph G2 (which is used for visuaization). 
        ie:For an edge A->B , if A > B then swaps A and B attributes.
        Causes problem only in visualization.
        '''
        for node in G2.nodes:
            if node['id'] == edge['from']:
                left_end = node['node_type'] + " " + node['id']
            if node['id'] == edge['to']:
                right_end = node['node_type'] + " " + node['id']
            
            if edge['link_ID'] > index + 1 :
                left_end, right_end = right_end, left_end

        #Adding attributes
        edge["title"] = "Link Attributes : <br>  <br> "
        edge["title"] += f"Link ID : {edge['link_ID']}  <br> " 
        edge["title"] += f"Capacity : {edge['capacity']} Mbps  <br>  Latency : {edge['latency']} ms  <br> <br>"
        
        #Left end attributes
        left_end_node_type = G.nodes[edge['from']]['node_type']
        
        edge["title"] += f"---Left End :{left_end}  --- <br> "
        
        if left_end_node_type != 'Hub':    
            edge['title'] += f"MAC : {edge['left_end']['MAC']}  <br> "
            edge['title'] += f"Gateway : {edge['left_end']['Gateway']} <br> "
            if left_end_node_type != 'L2 Switch':
                edge['title'] += f"IP :  {edge['left_end']['IP']} <br> "
                edge['title'] += f"Mask : {edge['left_end']['Mask']} <br> "
                if left_end_node_type == 'Router':
                    edge['title'] += f"NAT : {edge['left_end']['NAT']} <br>"
                if left_end_node_type == 'Server PC' or left_end_node_type == 'Client PC':
                    edge['title'] += f"DNS : {edge['left_end']['DNS']} <br>"
                    
        edge['title'] += "<br>"
        
            
        right_end_node_type = G.nodes[edge['to']]['node_type']
        #Right end attributes 
        edge["title"] += f"---Right End :  {right_end}--- <br> "
        if right_end_node_type != 'Hub':
            edge['title'] += f"MAC : {edge['right_end']['MAC']} <br> "
            edge['title'] += f"Gateway : {edge['right_end']['Gateway']} <br> "
            if right_end_node_type != 'L2 Switch' :
                edge['title'] += f"IP :  {edge['right_end']['IP']} <br> "
                edge['title'] += f"Mask : {edge['right_end']['Mask']} <br> "    
                if right_end_node_type == 'Router':
                    edge['title'] += f"NAT : {edge['right_end']['NAT']} <br>"
                if right_end_node_type == 'Server PC' or left_end_node_type == 'Client PC':
                    edge['title'] += f"DNS : {edge['right_end']['DNS']} <br>"

        edge['title'] += "<br>"
 
        
        #Edge attributes - Viewed on edge
        #edge["label"] = f"{edge['capacity']}Mbps"
               

    #Some initial options and display
    #G2.set_edge_smooth('discrete')
    G2.toggle_physics(False)
    G2.barnes_hut()   
    #G2.force_atlas_2based()
    G2.show(filename + '_visualiztion.html')
    


#Finds subnets in a given network - Returns a list of nx graph Objects - May need expansion  to include each router at its subnet
def find_subnets():
    G3 = G.copy()    
    for node in list(G3.nodes): 
        if G3.nodes[node]['node_type'] == 'Router':
            G3.remove_node(node)

    S = [G3.subgraph(c) for c in nx.connected_components(G3)]
    return S


#Validates if a MAC address is unique at its subnet
def validate_MAC_address():

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
                            print(f"Node: {node}, has the same MAC address as node: {node_help_list[node_2]} at subnet: {adapter.Gateway}/{IPAddress(adapter.Mask).netmask_bits()}")
            
            del node_help_list[0]

#Validates the IP addresses
'''
def validate_IP_address():

    #Checks if IP belongs to its subnet
    for subnet in network_subnets: 
        for node in subnet: 
            for i in range(len(subnet.nodes[node]['network_adapters'])):
                subnet_gateway_address = subnet.nodes[node]['network_adapters'][i].Gateway
                ip_address = subnet.nodes[node]['network_adapters'][i].IP
                subnet_mask = '/' + str(IPAddress(subnet.nodes[node]['network_adapters'][i].Mask).netmask_bits())
                
                if not IPAddress(ip_address) in IPNetwork(subnet_gateway_address + subnet_mask):
                    print(f"Node's {node} IP address: {ip_address}  does not belong at its subnet {subnet_gateway_address + subnet_mask}")
    
    #Checks if an IP address is unique
    
    #For every node
    for index, node in enumerate(G.nodes):
        node_help_list = list(G.nodes)
        
        #For every nodes adapter
        for adapter in G.nodes[node]['network_adapters']: 

            #For every other node
            for node_2 in range(index+1, len(node_help_list)): 
                    
                    #Check with every adapter on the other node
                    for adapter_2 in G.nodes[node_help_list[node_2]]['network_adapters']: 
                        if adapter.IP == adapter_2.IP: 
                            print(f"Node: {node} with IP address: {adapter.IP}, has the same IP address as node: {node_help_list[node_2]} with IP address: {adapter_2.IP}")

    #TODO NAT recognition

'''

#Help function that prints every nodes network adapters
def show_network_adapters(): 
    for node in G.nodes:
        for i in range(len(G.nodes[node]['network_adapters'])) :
            print(f"Node: {node}, Type: {G.nodes[node]['node_type']} - Network Adapters: \n {G.nodes[node]['network_adapters'][i].__str__()}")
    



#Main    
if __name__ == "__main__" : 
    
    #Parse the tgf file
    parse_tgf_file()

    #Find network adapters from edge attributes
    #find_adapters()
    
    #Find network subnets
    network_subnets = find_subnets()
    
    #Validate MAC addresses
    #validate_MAC_address()
    
    #Validate IP addresses
    #validate_IP_address()
    
    #Draw network graph
    draw_graph()
    
    show_network_adapters()
  
