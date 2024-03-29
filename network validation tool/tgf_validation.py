""" TGF Validator

    This module is used to validate the format and the values of the
    uninitialized TGF file.

    If error is occured, an error message is printed in the console
    that specifies the error and parsing is terminated.

    This modules functions are called by the TFG parser while parsing the topology


 """

from os import error

# Acceptable node attribute values
ACCEPTABLE_NODE_ATTR  = {'Client_PC', 'Server_PC', 'Router', 'Switch', 'Hub'}

ACCEPTABLE_LINK_ATTR = {'link_ID', 'left_end', 'right_end', 'capacity', 'latency'}

TAB = "    "


def print_error_msg(filename: str, error_msg: str) -> None:
    """ Prints the error message and exits
    
    Parameters
    ----------
    filename : str
        The name of the file the topology is located.
    error_msg : str
        Error message decribing the found error

    
    Returns
    -------
    None

    """
    
    print(f"Network topology file error at file: {filename}\n{TAB}-{error_msg}")
    exit()


def is_unique_node(filename: str, nodes: dict, node_id: str) -> None:
    """ Checks that every new parsed node is defined only once.
    It does that by comparing the new node is with the already
    parsed nodes. If duplication found the parsing is terminated

    Parameters
    ----------
    filename : str
         The name of the file the topology is located.
    nodes : dict
        Dictionary containing nodes with its attributes
        Example
            {
                'pc1': {'node_type': 'Client_PC'}, 
                'pc2': {'node_type': 'Client_PC'}, 
                'pc3': {'node_type': 'Client_PC'}
            }
    node_id: str
        The latest parsed node
    
    Returns
    --------
    None    
    
    """

    if node_id in nodes:
        error_msg = f"Node dublication error: Node: {node_id} is already defined once!"
        print_error_msg(filename, error_msg)
    

def is_unique_edge(filename: str, edges: dict, edge: str) -> None:
    """ Checks that every new parsed edge is defined only once.
    It does that by comparing the new edge with the already
    parsed edges. If duplication found the parsing is terminated

    Note: The graph is not Directional, so ie. edge 1->2 is same as
        edge 2->1
    
    Parameters
    ----------

    filename : str
         The name of the file the topology is located.
    edges : dict
        Dictionary containing the edges with its attributes
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
    edge : str
        The new parsed edge
    
    Returns
    -------
    None
    
    """

    if edge in edges: 
        error_msg = f"Edge dublication error: Edge ({edge}) is already defined once!"
        print_error_msg(filename, error_msg)
    
    #Reversing edge
    temp_edge = edge.split(" ")
    reversed_edge = f"{temp_edge[1]} {temp_edge[0]}"
    
    if reversed_edge in edges:
        error_msg = f"Edge dublication error: Edge ({edge}) is already defined reversed!"
        print_error_msg(filename, error_msg)
    

def validate_node_attributes(filename: str, node_id: str, node_attr: dict) -> None:
    """ Checks that the parsed node attributes and values are valid
    
    Parameters
    ----------
    filename : str
         The name of the file the topology is located.
    
    node_id : str
        The id of the last parsed node
    node_attr dict
        A dict that containt the nodes attributes
        Example:
             {'node_type': 'Client_PC'}

    Return
    ------
    None
    """


    def validate_node_attr_type() -> None:
        """ Checks that a node has the correct attributes according
        to the format.

        """
        
        invalid_node_attr = set(node_attr) - {'node_type'}
        if invalid_node_attr:
            error_msg = f"Node Attribute Type Error: {invalid_node_attr} are invalid at node {node_id}"
            print_error_msg(filename, error_msg)

    def validate_node_attr_value() -> None:
        """ Checks that nodes attributes have valid values
        """


        node_type = node_attr.get("node_type")
        
        if node_type not in ACCEPTABLE_NODE_ATTR:
            error_msg = f"Node Attribute Value Error: {node_type}, at node: {node_id} is not a valid node type value"
            print_error_msg(filename, error_msg)

    validate_node_attr_type()
    validate_node_attr_value()


def validate_edge_attributes(filename: str, edge: str, edge_attr: dict) -> None:
    """ Checks that the parsed edge attributes and values are valid
    
    Parameters
    ----------
    filename : str
         The name of the file the topology is located.
    
    edge : str
        The parsed edge
    edge_attr : dict
        A dict that containt the edgess attributes
        Example:
            {
            'link_ID': '1', 
            'left_end': {'if_id': 'eth01'}, 
            'right_end': {'if_id': 'eth01'}, 
            'capacity': '100', 'latency': '5'
            }

    Return
    ------
    None
    
    """
    
    print(f"Edge: {edge_attr}")

    def validate_edge_attribute_type():
        """ Checks that an edge has the correct attributes according
        to the format."""
        
        missing_attr_set = ACCEPTABLE_LINK_ATTR - set(edge_attr)    
        invalid_attr_set = set(edge_attr) - ACCEPTABLE_LINK_ATTR
        found_invalid_parsed_attr = False
        interface_missing = False

        error_msg = ''
        if missing_attr_set:
            error_msg += f"Edge Attribute Type Error: Attributes {missing_attr_set} are missing from edge ({edge})\n" 
            found_invalid_parsed_attr = True

        if invalid_attr_set:
            error_msg += f"\nEdge Attribute Type Error:Attributes {invalid_attr_set} are invalid or misspelled at edge ({edge})" 
            found_invalid_parsed_attr = True
            
        if found_invalid_parsed_attr:
            print_error_msg(filename, error_msg)
        
        if 'if_id' not in edge_attr['left_end']:
            error_msg = f"Edge Attribute Type Error: 'if_id' is missing from 'left_end' at edge ({edge})\n"
            interface_missing = True
        
        if 'if_id' not in edge_attr['right_end']:
            error_msg = f"Edge Attribute Type Error: 'if_id' is missing from 'right_end' at edge ({edge})\n"
            interface_missing = True
        
        if interface_missing:
            print_error_msg(filename, error_msg)
        



    def validate_edge_attributes_value():
        """ Checks that edges attributes have valid values
        """
        link_id = edge_attr['link_ID']
        if link_id.isdecimal():
            if int(link_id) <= 0:
                error_msg = f"Edge Attribute Value Error: Invalid link ID value at edge ({edge})  -Must be an integer, greater than 0"
                print_error_msg(filename, error_msg)
        else:
            error_msg = f"Edge Attribute Value Error: Invalid link ID value at edge ({edge}) -Must be an integer, greater than 0"
            print_error_msg(filename, error_msg)
        
        # Capacity value validation
        capacity = edge_attr['capacity']
        if capacity.isdecimal():
            if int(capacity) <= 0:
                error_msg = f"Edge Attribute Value Error: Invalid capacity value at edge ({edge}) -Must be an integer, greater than 0"
                print_error_msg(filename, error_msg)
        else:
            error_msg = f"Edge Attribute Value Error:  Invalid capacity value at edge ({edge}) -Must be an integer, greater than 0"
            print_error_msg(filename, error_msg)
           

        # Latency value validation
        latency = edge_attr['latency']
        if latency.isdecimal():
            if int(latency) <= 0:
                error_msg = f"Edge Attribute Value Error: Invalid latency value at edge ({edge}) -Must be an integer,greater than 0"
                print_error_msg(filename, error_msg)
        else:
            error_msg = f"Edge Attribute Value Error: Invalid latency value at edge ({edge}) -Must be an integer,greater than 0"
            print_error_msg(filename, error_msg)
           

    validate_edge_attribute_type()
    validate_edge_attributes_value()