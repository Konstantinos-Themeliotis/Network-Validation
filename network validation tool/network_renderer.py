""" The network graph renderer
    
    The network renderer is responsible for visualizing the network topology.
    Using the pyvis libary, takes as input a NetworkX DiGraph and produces a 
    pyvis graph that handles the visualization.

    The result is a HTML file containing the visualized network topology

"""

import networkx as nx
from pyvis.network import Network
import yaml
import os.path


class Renderer():
    """ Class for graph Renderer

    Attributes
    ----------
    net_graph : nx.DiGraph
        The nx.DiGraph object containing the network topology
    help_net_graph : nx.DiGraph
        A help nx.Digraph object containing the network topology
    filename : str
        String containing the output file containing the HTML
        visualization fil
    path : str
        The directory path were the visualization file will be created
    
    """
    
    def __init__(self, net_graph: nx.DiGraph, help_net_graph: nx.DiGraph, filename: str, path: str) -> None:
        """ Class constructor
        
        """

        # Configuration data
        themes_dir_path = self.find_path()
        
        # The choice of the viz theme
        vis_theme_option = self.parse_theme_option(themes_dir_path)
        
        # Parsed theme data
        vis_theme_data = self.parse_theme(themes_dir_path, vis_theme_option)
        
        # Pyvis network graph
        self.vis_graph = Network(height = '100%', width = '100%')
        
        self.set_theme(vis_theme_data)
        self.net_graph = net_graph

        # Translating nx.Digraph to pyvis graph 
        self.vis_graph.from_nx(help_net_graph)
        
        self.filename = filename
        self.path = path



    def find_path(self) -> str:
        """ Returns the path were the visualization themes and
            theme options are stored.

            Visualization themes and theme options are stored in seperate YAML file
        
        """    
        themes_dir = 'themes'
        themes_path = f"{os.path.dirname(os.path.realpath(__file__))}\\{themes_dir}"
        return themes_path

    
    def parse_theme_option(self, path: str) -> str:
        """ Reads theme option
        
            In theme option we specify which theme we want to 
            use to visualize our network.
            Returns the theme choice the user made

        """
        
        themes_file = "theme_option.yml"
        with open(path + "\\" + themes_file, 'r') as cf:		
            try:
                theme_option = yaml.load(cf, Loader = yaml.FullLoader)
            except yaml.YAMLError as exc:
                print(exc)
        
        return theme_option.get('theme_option')

    
    def parse_theme(self, path: str, theme_option: str) -> None:
        """ Parses theme

            Parses the theme the user selected at theme_option
            All the visualization themes are stored at the same YAML file.
        
        """
        
        vis_themes_file = "vis_themes.yml"
        with open(path + "\\" + vis_themes_file, 'r') as cf:		
        
            try:
                vis_theme_data = yaml.load(cf, Loader = yaml.FullLoader)
            except yaml.YAMLError as exc:
                print(exc)
        
        return vis_theme_data.get(theme_option)


    def set_theme(self, vis_theme: dict) -> None:
        """ Sets the visualization theme

            Sets the visualization theme we parsed in the pyvis graph

        """
        self.vis_graph.bgcolor = vis_theme["colors"]["bgcolor"]
        self.vis_graph.font_color = vis_theme["colors"]["font_color"]
        self.icons = vis_theme["icons"]
    

    def add_node_attr(self) -> None:
        """ Add nodes attribute for visualization
        
            For every node in the visualization graph, eg a Client PC, adds its attributes
            needed for the graph visualization
        """
     
        for node in self.vis_graph.nodes: 
            
            node['size'] = 30
            node['label'] = f"-{node['label']}-"
            node['font']['size'] = 20
            node['shadow'] = True
            
            # Add every node's IP address under its icon 
            for interface in self.net_graph.nodes[node['id']]['network_interfaces']:
                if node['node_type'] in {"Client_PC", "Server_PC", "Router"} :
                    node['label'] += "\n" + str(interface.ip) 
        
            # Viewed when mouse is over the node
            node['title'] = node['node_type'] + ' : ' + node['id'] + "<br>" 
            node['shape'] = 'image'
            node['image'] = self.icons[node["node_type"]]

    
    def add_edge_attr(self) -> None:
        """ Add edge attributes for visualization
        
            For every edge in the visualization graph, eg a Client PC 
            adds its attributes needed for the graph visualization
        """

        for edge in self.vis_graph.edges:
            for node in self.vis_graph.nodes:
                if node['id'] == edge['from']:
                    left_end = node['node_type'] + " " + node['id']
                if node['id'] == edge['to']:
                    right_end = node['node_type'] + " " + node['id']
        
        
            # Edge options
            edge['width'] = 3
            
            # Link attributes
            edge["title"] = "Link Attributes : <br>  <br> "
            edge["title"] += f"Link ID : {edge['link_ID']}  <br> " 
            edge["title"] += f"Capacity : {edge['capacity']} Mbps  <br>  Latency : {edge['latency']} ms  <br> <br>"
        
            # Left end attributes
            left_end_node_type = self.net_graph.nodes[edge['from']]['node_type']
            edge["title"] += f"---Left End :{left_end}  --- <br> "
            edge["title"] += f"Interface : {edge['left_end']['if_id']} <br> "
            if left_end_node_type != 'Hub':    
                edge['title'] += f"mac : {edge['left_end']['mac']}  <br> "
                if left_end_node_type != 'Switch':
                    edge['title'] += f"ip :  {edge['left_end']['ip']} <br> "
                    edge['title'] += f"mask : {edge['left_end']['mask']} <br> "
                    edge['title'] += f"gateway : {edge['left_end']['gateway']} <br> "
                    edge['title'] += f"dns : {edge['left_end']['dns']} <br>"
                    if left_end_node_type == 'Router':
                        edge['title'] += f"nat : {edge['left_end']['nat']} <br>"
                        if edge['right_end']['nat'] == 'enabled':
                            edge['title'] += f"public ip: {edge['right_end']['public_ip']}"

            else:
                edge['title'] += "I am a Hub, I am kinda dump" 

            edge['title'] += "<br>"           
            right_end_node_type = self.net_graph.nodes[edge['to']]['node_type']
            
            # Right end attributes 
            edge["title"] += f"---Right End :  {right_end}--- <br> "
            edge["title"] += f"Interface : {edge['right_end']['if_id']} <br> "
            if right_end_node_type != 'Hub':
                edge['title'] += f"mac : {edge['right_end']['mac']} <br> "
                if right_end_node_type != 'Switch' :
                    edge['title'] += f"ip :  {edge['right_end']['ip']} <br> "
                    edge['title'] += f"mask : {edge['right_end']['mask']} <br> "    
                    edge['title'] += f"gateway : {edge['right_end']['gateway']} <br> "
                    edge['title'] += f"dns : {edge['right_end']['dns']} <br>"
                    if right_end_node_type == 'Router':
                        edge['title'] += f"nat : {edge['right_end']['nat']} <br>"
                        if edge['right_end']['nat'] == 'enabled':
                            edge['title'] += f"public ip: {edge['right_end']['public_ip']}"
            else:
                edge['title'] += "I am a Hub, I am kinda dump <br> No attributes for me"
            
            edge['title'] += "<br>"

    
    def set_options(self) -> None:
        """ Init options for the graph 

            Sets some necessery option for the pyvis graph
        """
        
        # Set edge weight
        for edge in self.vis_graph.edges:
            edge['weight'] = 10
        
        self.vis_graph.toggle_physics(False)
        self.vis_graph.barnes_hut()
        self.vis_graph.show_buttons()
   
    def render(self) -> None:
        """ Start rendering"""

        self.add_node_attr()
        self.add_edge_attr()
        self.set_options()
        output_filename = self.path + "\\" + self.filename + '_vis.html'
        self.vis_graph.show(output_filename)