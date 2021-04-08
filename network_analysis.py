"""Network Validation

This script,for the time being, reads a computer network graph and
visualizes it. 

The graph is written in Trivial Graph Format (.tgf)
and exported in a HTML file.

For the network analysis part, the networkx library is being used.
For the network visualization, the pyvis library is being used. 
Pyvis is built around javascript library visjs.
ast is being used for attribute parsing. 

The graph that is produced is interactive, meaning you can drag n drop the nodes
see their attributes when the mouse is over the node etc etc.There is a control panel
to change some of the graphs values-attributes

"""


import networkx as nx
from pyvis.network import Network
import ast
import matplotlib.pyplot as plt
import network_adapter as na


G = nx.Graph()
G2 = Network(height = '100%', width = '100%')


#Acceptable node attributes and acceptable node attribute values
node_acceptable_attr = {
        'node_type' : ['Client PC', 'Server PC','Router','Switch','Hub']
        }

#Acceptable edge attributes and acceptable edge attribute values-TODO validation
edge_acceptable_attr = ['link_ID', 'left_end', 'right_end', 'capacity', 'latency']
node_end_acceptable_attr = ['MAC', 'IP', 'MASK', 'Gateway', 'DNS']

#The icon map for different node types used for vizualization, icons are stored in my Github account
icons_map = {
        'Client PC' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/coding.png' , 
        'Server PC' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/data-server.png' , 
        'Router' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/router12.png' ,
        'Switch' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/network-hub.png' , 
        'Hub' : 'https://raw.githubusercontent.com/dperpel/Network-Validation/main/icons/hub1.png'
        }


#Tgf file parser
def parse_tgf_file():
    nodes_parsing_completed = False
    nodes = []
    edges = []

    with open("network_graph_2.tgf") as f:
        while True:    
            #Reading the file line-line
            line = f.readline()

            #End of file
            if not line:
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

    for node in G.nodes: 
        G.nodes[node]["network_adapters"] = []

    #Creating network Adapter object for every different network adapter
    for edge in edges: 
        
        #Creating adapter objects
        left_end_adapter = na.Adapter(edge[2]['left_end']["MAC"],edge[2]['left_end']["IP"],edge[2]['left_end']["Mask"],edge[2]['left_end']["Gateway"],edge[2]['left_end']["DNS"])
        right_end_adapter = na.Adapter(edge[2]['right_end']["MAC"],edge[2]['right_end']["IP"],edge[2]['right_end']["Mask"],edge[2]['right_end']["Gateway"],edge[2]['right_end']["DNS"])

        found_left_adapter = False 
        found_right_adapter = False
        
        #Left end adapter check
        if not G.nodes[edge[0]]['network_adapters']: 
            G.nodes[edge[0]]['network_adapters'].append(left_end_adapter)
        else:
            for adapter in G.nodes[edge[0]]['network_adapters']:
                if adapter == left_end_adapter: 
                    found_left_adapter = True

            if not found_left_adapter: 
                  G.nodes[edge[0]]['network_adapters'].append(left_end_adapter)

        #Right end adapter check
        if not G.nodes[edge[1]]['network_adapters']: 
            G.nodes[edge[1]]['network_adapters'].append(right_end_adapter)
        else:
            for adapter in  G.nodes[edge[1]]['network_adapters']:
                if adapter == right_end_adapter: 
                    found_right_adapter = True

            if not found_right_adapter: 
                  G.nodes[edge[1]]['network_adapters'].append(right_end_adapter)

 

#Graph visualization   
def draw_graph(): 
    
    #Adding node attributes for visualization - Viewed when mouse is over the node
    for node in G2.nodes:
        node['title'] = node['node_type'] + ' : ' + node['id'] 
        node['shape'] = 'image'
        node['image'] = icons_map[node['node_type']]
        if node['node_type'] == 'Client PC':
            node["size"] = 22
        else : 
            node["size"] = 25
         
    #Adding edge attributes for visualization - Viewed when mouse is over the link     
    for edge in G2.edges: 
        edge["title"] = "Link Attributes : <br>  <br> "
        
        edge["title"] += f"Link ID : {edge['link_ID']}  <br> " 
        edge["title"] += f"Capacity : {edge['capacity']} Mbps  <br>  Latency : {edge['latency']} ms  <br> <br>"
        
        #Left end attributes
        edge["title"] += f"---Left End : {G.nodes[edge['from']]['node_type']} {edge['from']} --- <br> "
        edge['title'] += f"MAC : {edge['left_end']['MAC']}  <br> "
        edge['title'] += f"IP :  {edge['left_end']['IP']} <br> "
        edge['title'] += f"Mask : {edge['left_end']['Mask']} <br> "
        edge['title'] += f"Gateway : {edge['left_end']['Gateway']} <br> "
        edge['title'] += f"DNS : {edge['left_end']['DNS']} <br> <br> "
        
        #Right end attributes
        edge["title"] += f"---Right End :  {G.nodes[edge['to']]['node_type']} {edge['to']}--- <br> "
        edge['title'] += f"MAC : {edge['right_end']['MAC']} <br> "
        edge['title'] += f"IP :  {edge['right_end']['IP']} <br> "
        edge['title'] += f"Mask : {edge['right_end']['Mask']} <br> "    
        edge['title'] += f"Gateway : {edge['right_end']['Gateway']} <br> "
        edge['title'] += f"DNS : {edge['right_end']['DNS']} "  
        
        #Edge attributes - Viewed on link -TODO
        edge["label"] = "Unknown"
       

    #Some initial options and display
    G2.set_edge_smooth('discrete')
    G2.toggle_physics(False)
    G2.barnes_hut()   
    G2.show('network_visualization.html')
    


#Finds subnets in a given network - Returns a list of nx graph Objects
def find_subnets():
    G3 = G.copy()    
    for node in list(G3.nodes): 
        if G3.nodes[node]['node_type'] == 'Router':
            G3.remove_node(node)

    S = [G3.subgraph(c) for c in nx.connected_components(G3)]
    return S


#Help function that prints every node network adapters
def print_mac(): 
    for node in G.nodes:  
        print(f"Node: {node}  Newtork Adapters: {[G.nodes[node]['network_adapters'][i].MAC  for i in range(len(G.nodes[node]['network_adapters']))]}")



#Checks if a network adapter is unique
def check_unique_adress():
    network_subnets = find_subnets()

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
                            print(f"Node: {node}, has the same MAC adress at node: {node_help_list[node_2]} at subnet: {sub_index+1} ")
            
            del node_help_list[0]


    

    
    
#Main    
if __name__ == "__main__" : 
    parse_tgf_file()
    #print_mac()
    #check_unique_adress()
    draw_graph()
 

