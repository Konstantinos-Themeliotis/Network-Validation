import networkx as nx
from pyvis.network import Network

class Renderer():
    def __init__(self, net_graph: nx.DiGraph, help_net_graph: nx.DiGraph, vis_theme: dict, filename: str) -> None:
        self.vis_graph = Network(height = '100%', width = '100%')
        self.vis_graph.bgcolor = vis_theme["colors"]["bgcolor"]
        self.vis_graph.font_color = vis_theme["colors"]["font_color"]
        
        self.net_graph = net_graph
        self.vis_graph.from_nx(help_net_graph)
        
        self.icons = vis_theme["icons"]
        self.filename = filename

    def add_node_attr(self):
        """ Add nodes attribute for visualization"""
     
        for node in self.vis_graph.nodes: 
            
            node['size'] = 30
            node['label'] = f"-{node['label']}-"
            
            # Add every node's IP address under its icon 
            for interface in self.net_graph.nodes[node['id']]['network_interfaces']:
                if node['node_type'] in {"Client_PC", "Server_PC", "Router"} :
                    node['label'] += "\n" + str(interface.ip) 
        
            # Viewed when mouse is over the node
            node['title'] = node['node_type'] + ' : ' + node['id'] + "<br>" 
            node['shape'] = 'image'
            node['image'] = self.icons[node["node_type"]]

    def add_edge_attr(self):
        """ Add edge attributes for visualization"""

        for index, edge in enumerate(self.vis_graph.edges):
            for node in self.vis_graph.nodes:
                if node['id'] == edge['from']:
                    left_end = node['node_type'] + " " + node['id']
                if node['id'] == edge['to']:
                    right_end = node['node_type'] + " " + node['id']
        
        
            # Link attributes
            edge["title"] = "Link Attributes : <br>  <br> "
            edge["title"] += f"Link ID : {edge['link_ID']}  <br> " 
            edge["title"] += f"Capacity : {edge['capacity']} Mbps  <br>  Latency : {edge['latency']} ms  <br> <br>"
        
            # Left end attributes
            left_end_node_type = self.net_graph.nodes[edge['from']]['node_type']
            edge["title"] += f"---Left End :{left_end}  --- <br> "
            
            if left_end_node_type != 'Hub':    
                edge['title'] += f"mac : {edge['left_end']['mac']}  <br> "
                if left_end_node_type != 'Switch':
                    edge['title'] += f"ip :  {edge['left_end']['ip']} <br> "
                    edge['title'] += f"mask : {edge['left_end']['mask']} <br> "
                    edge['title'] += f"gateway : {edge['left_end']['gateway']} <br> "
                    edge['title'] += f"dns : {edge['left_end']['dns']} <br>"
                    if left_end_node_type == 'Router':
                        edge['title'] += f"nat : {edge['left_end']['nat']} <br>"
            else:
                edge['title'] += "I am a Hub, I am kinda dump" 

            edge['title'] += "<br>"           
            right_end_node_type = self.net_graph.nodes[edge['to']]['node_type']
            
            # Right end attributes 
            edge["title"] += f"---Right End :  {right_end}--- <br> "
            if right_end_node_type != 'Hub':
                edge['title'] += f"mac : {edge['right_end']['mac']} <br> "
                if right_end_node_type != 'Switch' :
                    edge['title'] += f"ip :  {edge['right_end']['ip']} <br> "
                    edge['title'] += f"mask : {edge['right_end']['mask']} <br> "    
                    edge['title'] += f"gateway : {edge['right_end']['gateway']} <br> "
                    edge['title'] += f"dns : {edge['right_end']['dns']} <br>"
                    if right_end_node_type == 'Router':
                        edge['title'] += f"nat : {edge['right_end']['nat']} <br>"
            else:
                edge['title'] += "I am a Hub, I am kinda dump <br> No attributes for me"
            
            edge['title'] += "<br>"

    def set_options(self):
        """ Init options for the graph """
        # self.vis_graph.set_edge_smooth('discrete')
        self.vis_graph.toggle_physics(False)
        self.vis_graph.barnes_hut()   
    
    def render(self):
        self.add_node_attr()
        self.add_edge_attr()
        self.set_options() 
        self.vis_graph.show(self.filename + '_vis.html')