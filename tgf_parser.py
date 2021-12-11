import abc
import ast


class Abstract_TFG_Parser(object, metaclass = abc.ABCMeta):
    """ Abstract tgf parser"""

    def __init__(self, path: str, filename: str) -> None:
        """ Parent initialization function, called by both children"""

        # Restrict creating abstract class instance
        if self.__class__ is Abstract_TFG_Parser:
            raise TypeError("Abstract class cannot be instantiated")

        self.path = path
        self.filename = filename
        
        # FIXME Maybe not needed as an attribute
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
        pass 


    def start_parsing(self) -> None:
        """Template method that start the network topology parsing"""
        
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
    """ The tgf parser used to parse the unconfigurated network topology"""
    
    def __init__(self, path, filename) -> None:
        super().__init__(path, filename)
        self.nodes = {}
        self.edges = {}
    
    # TODO validation
    def parse_nodes(self, line: str) -> None:
        """ Concrete method for parsing the uncofigurated nodes"""
         
        node_id = line.split("~")[0].strip()  
        node_attr = ast.literal_eval(line.split("~")[1].strip())
        self.nodes[node_id] = node_attr

    # TODO validation
    def parse_edges(self, line: str) -> None :
        """ Concrete method for parsing the uncofigurated edges"""
        
        left_end_node_id = line.split("~")[0].split(" ")[0].strip()
        right_end_node_id = line.split("~")[0].split(" ")[1].strip()
        edge_attr = ast.literal_eval(line.split("~")[1].strip())                
        key = f"{left_end_node_id} {right_end_node_id}"               
        self.edges[key] = edge_attr

    def parse_network_topology(self) -> tuple(dict, dict):
        """ Function that start parsing  """
        
        self.start_parsing()
        return self.nodes, self.edges


# FIXME Rename this class, it's not a good name - remember to change the object
# created at network validation file
class Init_TGF_Parser(Abstract_TFG_Parser):
    """ The tgf parser used to parse the configurated network topology"""

    def __init__(self, path: str, filename: str) -> None:
        super().__init__(path, filename)
        self.nodes = []
        self.edges = []

    # TODO validation
    def parse_nodes(self, line: str) -> None:
        """ Concrete method for parsing the configurated nodes"""

        node_id = line.split("~")[0].strip()  
        node_attr = ast.literal_eval(line.split("~")[1].strip())       
        #validate_node_attributes(node_id, node_attr)
        node_tuple = (node_id, node_attr)
        self.nodes.append(node_tuple)

    # TODO Validation
    def parse_edges(self, line: str) -> None:
        """ Concrete method for parsing the configurated edges"""

        left_end_node_id = line.split("~")[0].split(" ")[0].strip()
        right_end_node_id = line.split("~")[0].split(" ")[1].strip()
        edge_attr = ast.literal_eval(line.split("~")[1].strip())
        #validate_edge_attributes(nodes, left_end_node_id, right_end_node_id, edge_attr)     
        edge_tuple = (left_end_node_id, right_end_node_id, edge_attr)
        self.edges.append(edge_tuple)                         


    def parse_network_topology(self) -> tuple(list, list):
        """ Function that starts parsing"""

        self.start_parsing()
        return self.nodes, self.edges
