""" The parser for the Trivial Graph Format (TGF)

    TGF is a simple text-based adjecency list file format for descibing graphs.
    For the purpose of our project we expanded the format to support more
    complex attributes in its nodes and edges.
    
    In the process of a topology initialization we have 2 different TGF files:
    
    -   The first is a file descibing the netowrk topology with its nodes and
        edges without the network parameters as attributes.
    
    -   The second file uses the network interface configuration files to
        initialize the interfaces by adding them as attributs to nodes and edges.
    
    For the parser we implemented the Template design pattern to seperate
    the different steps between the unconfigurated and the configurated 
    TGF file

"""

import abc
import ast
import tgf_validation as val


class Abstract_TFG_Parser(object, metaclass = abc.ABCMeta):
    """ Abstract Base Class for tgf parser
    
    Attributes
    ----------
    path : str
         The complete path for the tgf topology file.
    filename : str
        The filename of the tgf topology file.
    line_counter : int
        Counter that specifies the line number that is being parsed
    nodes_parsing_completed : boolean
        Flag value, turns True when node parsing is completed, indicating
        the parser to start parsing the edges.

    """

    def __init__(self, path: str, filename: str) -> None:
        """Class constructor, called by both children
        
        """

        # Restrict creating abstract class instance
        if self.__class__ is Abstract_TFG_Parser:
            raise TypeError("Abstract class cannot be instantiated")

        self.path = path
        self.filename = filename
        
        self.line_counter = 0
        self.nodes_parsing_completed = False
    

    @abc.abstractmethod
    def parse_nodes(self, line: str) -> None:
        """ Abstact method for parsing nodes, implemented in each concrete class"""
        pass


    @abc.abstractmethod
    def parse_edges(self, line: str) -> None:
        """ Abstact method for parsing edges, implemented in each concrete class"""
        pass


    @abc.abstractmethod
    def parse_network_topology(self) -> None:
        """ Abstract method that start the topology parsing, implemented in each concrete class"""
        pass 


    def read_file(self) -> None:
        """ Template method that reads the toplogy file line by line.
        """
        
        with open(self.path + "\\" + self.filename) as f:
              while True:    
                
                # Reading the file line-line
                line = f.readline()
                self.line_counter += 1
                
                # End of file
                if not line:
                    break
                
                # Blank Line
                if line.isspace():
                    continue

                # Comments
                if '//' in line:
                    continue

                # Nodes from  edges seperator in tgf file
                if "#" in line: 
                    self.nodes_parsing_completed = True
                    continue
                            
                # Read until ";" character is read          
                while ";" not in line:
                    new_line = f.readline()
                    self.line_counter += 1
                    
                    if not new_line:
                        print(f"\n  File {self.filename}, line {self.line_counter-1}")
                        print("  SyntaxError: Break char ';' is missing\n")
                        exit()
                    
                    if new_line.isspace():
                        print(f"\n  File {self.filename}, line {self.line_counter-1}")
                        print("  SyntaxError: Found newline before break char ';' or is missing \n")
                        exit()
                    line += new_line
                
                line = line.strip(";\n")
                if not self.nodes_parsing_completed:
                    self.parse_nodes(line)
                else:
                    self.parse_edges(line)
            
            

class Def_TGF_Parser(Abstract_TFG_Parser):
    """ The Concrete class for tgf parser that is used to parse the 
        unconfigurated network topology

        Attributes
        ----------
        nodes : dictionary 
            Contains every parsed node
            Example:
                {
                    'pc1': {'node_type': 'Client_PC'}, 
                    'pc2': {'node_type': 'Client_PC'}, 
                    'pc3': {'node_type': 'Client_PC'}
                }
        edges : dictionary
            Contains every parsed edge
            Example:
            {
                'pc1 sw1': {
                    'link_ID': '1', 
                    'left_end': {'if_id': 'eth01'}, 
                    'right_end': {'if_id': 'eth01'}, 
                    'capacity': '100', 'latency': '5'},
                'pc2 sw1': {
                    'link_ID': '2', 
                    'left_end': {'if_id': 'eth01'}, 
                    'right_end': {'if_id': 'eth01'}, 
                    'capacity': '100', 'latency': '5'}
            }

    """
    
    def __init__(self, path, filename) -> None:
        """ Concrete Class constructor

       """


        super().__init__(path, filename)
        self.nodes = {}
        self.edges = {}



    def parse_nodes(self, line: str) -> None:
        """ Concrete method for parsing the uncofigurated nodes
     
        """
         
        node_id = line.split("~")[0].strip()  
        node_attr = ast.literal_eval(line.split("~")[1].strip())
        
        # Format and value validation for parsed data
        # If error occurs, parsing ends!
        val.is_unique_node(self.filename, self.nodes, node_id)
        val.validate_node_attributes(self.filename, node_id, node_attr)

        self.nodes[node_id] = node_attr


    def parse_edges(self, line: str) -> None :
        """ Concrete method for parsing the uncofigurated edges
 
        """
        
        left_end_node_id = line.split("~")[0].split(" ")[0].strip()
        right_end_node_id = line.split("~")[0].split(" ")[1].strip()
        edge_attr = ast.literal_eval(line.split("~")[1].strip())
        edge = f"{left_end_node_id} {right_end_node_id}"

        # Format and value validation for parsed data
        # If error occurs, parsing ends!
        val.is_unique_edge(self.filename, self.edges, edge)               
        val.validate_edge_attributes(self.filename, edge, edge_attr)                
        
        self.edges[edge] = edge_attr

    def parse_network_topology(self) -> tuple:
        """ Concrete function that starts parsing  
        
        """
        
        self.read_file()
        return self.nodes, self.edges



class Init_TGF_Parser(Abstract_TFG_Parser):
    """ The Concrete class for tgf parser that is used to parse the 
        configurated network topology
    
        Attributes
        ----------
        nodes : list
            List to contain the configurated nodes of the network
        edges : list
            List to contain the configurated edged of the network 
    """

    def __init__(self, path: str, filename: str) -> None:
        """ Concrete Class constructor

       """
        super().__init__(path, filename)
        self.nodes = []
        self.edges = []

    
    def parse_nodes(self, line: str) -> None:
        """ Concrete method for parsing the uncofigurated nodes
        
        """

        node_id = line.split("~")[0].strip()  
        node_attr = ast.literal_eval(line.split("~")[1].strip())       
        node_tuple = (node_id, node_attr)
        
        self.nodes.append(node_tuple)

    
    def parse_edges(self, line: str) -> None:
        """  Concrete method for parsing the cofigurated edges
        
        """

        left_end_node_id = line.split("~")[0].split(" ")[0].strip()
        right_end_node_id = line.split("~")[0].split(" ")[1].strip()
        edge_attr = ast.literal_eval(line.split("~")[1].strip())
        edge_tuple = (left_end_node_id, right_end_node_id, edge_attr)
        self.edges.append(edge_tuple)                         


    def parse_network_topology(self) -> tuple:
        """ Concrete function that starts parsing  
        
        """

        self.read_file()
        return self.nodes, self.edges
