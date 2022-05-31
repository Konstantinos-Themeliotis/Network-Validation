""" TODO: Description """

from os import error


ACCEPTABLE_NODE_ATTR  = {'Client_PC', 'Server_PC', 'Router', 'Switch', 'Hub'}

ACCEPTABLE_LINK_ATTR = {'link_ID', 'left_end', 'right_end', 'capacity', 'latency'}

TAB = "    "


def print_error_msg(filename: str, error_msg: str) -> None:
    print(f"Network topology file error at file: {filename}\n{TAB}-{error_msg}")
    exit()


def is_unique_node(filename: str, nodes: dict, node_id: str) -> None:
    """ Checks that every defined node is defined only once"""

    if node_id in nodes:
        error_msg = f"Node dublication error: Node: {node_id} is already defined once!"
        print_error_msg(filename, error_msg)
    

def is_unique_edge(filename: str, edges: dict, edge: str) -> None:
    """ Checks that every edge is defined only once"""

    if edge in edges: 
        error_msg = f"Edge dublication error: Edge ({edge}) is already defined once!"
        print_error_msg(filename, error_msg)
    
    temp_edge = edge.split(" ")
    reversed_edge = f"{temp_edge[1]} {temp_edge[0]}"
    
    if reversed_edge in edges:
        error_msg = f"Edge dublication error: Edge ({edge}) is already defined reversed!"
        print_error_msg(filename, error_msg)
    

def validate_node_attributes(filename: str, node_id: str, node_attr: dict) -> None:
    
    def validate_node_attr_type() -> None:
        invalid_node_attr = set(node_attr) - {'node_type'}
        if invalid_node_attr:
            error_msg = f"Node Attribute Type Error: {invalid_node_attr} are invalid at node {node_id}"
            print_error_msg(filename, error_msg)

    def validate_node_attr_value() -> None:
        node_type = node_attr.get("node_type")
        
        if node_type not in ACCEPTABLE_NODE_ATTR:
            error_msg = f"Node Attribute Value Error: {node_type}, at node: {node_id} is not a valid node type value"
            print_error_msg(filename, error_msg)

    validate_node_attr_type()
    validate_node_attr_value()


def validate_edge_attributes(filename: str, edge: str, edge_attr: dict) -> None:
    
    def validate_edge_attribute_type():
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