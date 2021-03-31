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

#Acceptable node attributes and acceptable node attribute values
node_acceptable_attr = {
        'node_type' : ['Client PC', 'Server PC','Router','Switch','Hub']
        }

#Acceptable edge attributes and acceptable edge attribute values
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
def parse_tgf_file() :
    nodes_parsing_completed = False
    nodes = []
    edges = []

    with open("graph3.tgf") as f :
        while True :    
            #Reading the file line-line
            line = f.readline()

            #End of file
            if not line :
                break
            
            #Nodes from  edges seperator in tgf file
            if "#" in line : 
                nodes_parsing_completed = True
                continue

            #Parsing nodes from file      
            if not nodes_parsing_completed : 
                node  = line.split("~")[0].strip() 
                node_attr = ast.literal_eval(line.split("~")[1].strip())
                
                #Validation check for node attributes-values
                for key in list(node_attr) :
                    if key in node_acceptable_attr : 
                        if node_attr[key] in node_acceptable_attr[key] : 
                            node_attr['network_adapters'] = []
                            node_tuple = (node, node_attr)
                            nodes.append(node_tuple)
                        else : 
                            print("Not acceptable " + key + " value at node: " + str(node))
                            exit()
                    else : 
                        print(key + " is not an acceptable attribute " + "at node: " + str(node))
                        exit()
                    
                
            #Parsing edges from file- TODO edge-attribute validation check
            else :
                edge_attr = ast.literal_eval(line.split("~")[1].strip())
                node_1 = line.split("~")[0].split(" ")[0].strip()
                node_2 = line.split("~")[0].split(" ")[1].strip()
                edge_tuple = (node_1, node_2, edge_attr)
                edges.append(edge_tuple)                         
    
    #Creating Graph
    G.add_nodes_from(nodes)
    G.add_edges_from(edges)

    #Creating network adapter object for every different network adapter
    for edge in edges : 
        network_adapter = na.Adapter(edge[2]['left_end']["MAC"])
        found = False 
        
        if not G.nodes[edge[0]]['network_adapters'] : 
            G.nodes[edge[0]]['network_adapters'].append(network_adapter)
        else :
            for item in  G.nodes[edge[0]]['network_adapters'] :
                if item == network_adapter : 
                    found = True

            if not found : 
                  G.nodes[edge[0]]['network_adapters'].append(network_adapter)

    for edge in edges : 
        network_adapter = na.Adapter(edge[2]['left_end']["MAC"])
        found = False 
        
        if not G.nodes[edge[1]]['network_adapters'] : 
            G.nodes[edge[1]]['network_adapters'].append(network_adapter)
        else :
            for item in  G.nodes[edge[1]]['network_adapters'] :
                if item == network_adapter : 
                    found = True

            if not found : 
                  G.nodes[edge[1]]['network_adapters'].append(network_adapter)


    
    
 

#Graph visualization   
def draw_graph() : 
    
    #Creating pyvis graph from networkx object
    G2 = Network(height = '100%', width = '100%')
    G2.from_nx(G)
    
    #Adding node attributes for visualization
    for node in G2.nodes :
        node["title"] = node['node_type'] + ' : ' + node['id'] 
        node['shape'] = 'image'
        node['image'] = icons_map[node["node_type"]]
        if node['node_type'] == 'Client PC':
            node["size"] = 22
        else : 
            node["size"] = 25
         
    #Adding edge attributes for visualization    
    
    for edge in G2.edges : 
        edge["title"] = "Attributes : " + '<br>' + '<br>'
        
        edge["title"] += "Link ID : " + str(edge['link_ID']) + '<br>'
        edge["title"] += "Capacity : " + str(edge['capacity']) + " Mbps" + '<br>' + "Latency : " + str(edge['latency']) + " ms" + '<br>' + '<br>'
        
        #Left end attributes
        edge["title"] += "---Left End :  " + str(G.nodes[edge['from']]['node_type']) + " " + str(edge['from']) + "---" + '<br>' 
        edge['title'] += 'MAC : ' + str(edge['left_end']['MAC']) + '<br>'
        edge['title'] += 'IP : ' + str(edge['left_end']['IP']) + '<br>' 
        edge['title'] += 'Mask : ' + str(edge['left_end']['Mask']) + '<br>'
        edge['title'] += 'Gateway : ' + str(edge['left_end']['Gateway']) + '<br>'
        edge['title'] += 'DNS : ' + str(edge['left_end']['DNS']) + '<br>'+ '<br>'
        
        #Right end attributes
        edge["title"] += "---Right End :  " + str(G.nodes[edge['to']]['node_type']) + " " + str(edge['to']) + "---" + '<br>'
        edge['title'] += 'MAC : ' + str(edge['right_end']['MAC']) + '<br>'
        edge['title'] += 'IP : ' + str(edge['right_end']['IP']) + '<br>'
        edge['title'] += 'Mask : ' + str(edge['right_end']['Mask']) + '<br>'    
        edge['title'] += 'Gateway : ' + str(edge['right_end']['Gateway']) + '<br>'
        edge['title'] += 'DNS : ' + str(edge['right_end']['DNS'])  
        
        edge["label"] = "Unknown"
        

    #Some initial options and display
    #G2.show_buttons()
    G2.set_edge_smooth('discrete')
    G2.toggle_physics(False)
    G2.barnes_hut()   
    G2.show('graph_visualization.html')
    


#Finds subnets in a given network - Returns a list of graph Objects
def find_subnet() :
    G3 = G.copy()    
    for node in list(G3.nodes) : 
        if G3.nodes[node]['node_type'] == 'Router' or G3.nodes[node]['node_type'] == 'Server PC' : 
            G3.remove_node(node)

    S = [G3.subgraph(c) for c in nx.connected_components(G3)]
    return S

#Checks if a network adapter is unique
def check_unique_adress() :
    network_subnets = find_subnet()
    #print(subnets[0].nodes['1']['network_adapters'][0].MAC)
    
    #print(list(network_subnets[0].nodes))
    
    #for every subnet
    for subnet in network_subnets :
        
        #for every node in subnet 
        for index, node in enumerate(subnet) :
            
            #for every adapter in node
            for adapter in subnet.nodes[node]['network_adapters'] : 
                
                #Checks with every other node
                for i, nod in enumerate(range(index + 1, len(list(subnet.nodes)))) : 
                    
                    #Check with every node adapter
                    for j, item in subnet.nodes[nod]['network_adapters'] : 
                        
                        if item == subnet.nodes[node]['network_adapters'][j] : 
                            print("Anteee")
                     




    

    
    
            
    
#Main    
if __name__ == "__main__" : 
    parse_tgf_file()
    check_unique_adress()
    #draw_graph()
    """
    for node  in G.nodes : 
        for i in range(len(G.nodes[node]["network_adapters"])) : 
            print( G.nodes[node]["network_adapters"][i].MAC)
    """

