"""
Network Validation ~Under construction!

"""

#Imports
import netaddr
import networkx as nx
import ast
from netaddr import *
import os.path
import pandas as pd
import yaml
import tgf_parser as tgf
import network_renderer as rd
import network_interface as nif


# Global variables
NETWORK_GRAPH = nx.DiGraph()    #network topology graph
HELP_NET_GRAPH = nx.DiGraph()   #help graph used for visualization

found_error = False
TAB = "    "

#TODO Maybe add the to config file. Acceptable attribute and attribute values
ACCEPTABLE_NODE_ATTR = {
    'node_type' : {'Client_PC', 'Server_PC', 'Router', 'Switch', 'Hub'},
    'routing_table' : {'dest', 'mask', 'next_hop'}
    }
ACCEPTABLE_LINK_ATTR = {'link_ID', 'left_end', 'right_end', 'capacity', 'latency'}
ACCEPTABLE_INTERFACE_ATTR = {
    'Client_PC' : {'if_id', 'mac', 'ip', 'mask', 'gateway', 'dns'},
    'Server_PC' : {'if_id', 'mac', 'ip', 'mask', 'gateway', 'dns'},
    'Router' : {'if_id', 'mac', 'ip', 'mask', 'gateway', 'dns', 'nat', 'public_ip'},
    'Switch' : {'if_id', 'mac'},
    'Hub' : {'if_id'}
    }



def find_path(filename: str, example: str) -> str:
    """ Checks that the configurated network topology file exists in examples directory"""
    
    current_directory_path = os.path.dirname(os.path.realpath(__file__))
    examples_directory = current_directory_path + "\\" + "topologies" + "\\" + example
    if filename not in os.listdir(examples_directory):
        print(f"-File {filename} does not exist in current directory\n")
        exit(0)

    return examples_directory


def parse_network(path: str, filename: str) -> None:
    """ Parses the network topology using the custom 'tgf_parser' parser module""" 
    
    parser = tgf.Init_TGF_Parser(path, filename)
    nodes, edges = parser.parse_network_topology()
    init_graphs(nodes, edges)


def init_graphs(nodes: list, edges: list):
    """ Initializes graphs after parsing is completed 
    Note: It would be better to create routing table Dataframes while parsing
    and add them directly as attributes to the graph. But pyvis can not handle them.
    So the NETWORK_GRAPH is first created simply, and then adds the objects as attributes
    
    """
    
    # Creating Networkx Graph
    NETWORK_GRAPH.add_nodes_from(nodes)
    NETWORK_GRAPH.add_edges_from(edges)
    HELP_NET_GRAPH.add_nodes_from(nodes)
    HELP_NET_GRAPH.add_edges_from(edges)

    # List with nodes interfaces added as attribute in every node
    for node in NETWORK_GRAPH.nodes:
        NETWORK_GRAPH.nodes[node]["network_interfaces"] = []    

    # Create interfaces from edge attributes
    create_interfaces()

    # #Creating routing table dataframes for every Router
    for node in NETWORK_GRAPH:
        if NETWORK_GRAPH.nodes[node]['node_type'] == 'Router':
            routing_table = pd.DataFrame(NETWORK_GRAPH.nodes[node]['routing_table'])
            NETWORK_GRAPH.nodes[node]['routing_table'] = routing_table    
    
    # Router addresses table
    create_router_addresses_table()
    
    # Find every routers -and in the future (refactoring) every nodes- connection
    # Needed for route validation
    find_ip_connections()


def create_interfaces() -> None:
    """ Creates the network interface objects from graph's edge attributes 
        
        -Scans through networks edges attributes to extract different
        network interfaces, creates network interface objects and adds them to
        each node, at network_interfaces field 
    """

    for edge in NETWORK_GRAPH.edges: 

        for index, end_node in enumerate(['left_end', 'right_end']):
            node_type = NETWORK_GRAPH.nodes[edge[index]]['node_type']

            if node_type == 'Hub':
                interface = nif.Interface(NETWORK_GRAPH.edges[edge][end_node])

            elif node_type == 'Router':
                interface = nif.RouterInterface(NETWORK_GRAPH.edges[edge][end_node]) 

            elif node_type == 'Switch':
                interface = nif.L2Interface(NETWORK_GRAPH.edges[edge][end_node])

            else:
                interface = nif.PcInterface(NETWORK_GRAPH.edges[edge][end_node])

            # The -not in- is based on the __eq__ func in the network interface object 
            if interface not in NETWORK_GRAPH.nodes[edge[index]]['network_interfaces']:
                NETWORK_GRAPH.nodes[edge[index]]['network_interfaces'].append(interface)
            elif node_type in {'Client_PC', 'Server_PC'}: 
                print(f"Warning: Duplicate network interface found on {edge[index]}")


def find_ip_connections() -> None:
    """ Find each routers ip connections/edges/link
        
        Notice:
            NOT a good function, refactoring needed above for a better solution,
            but for now it must be implemented for routing to work 
    """

    for node in NETWORK_GRAPH.nodes:
        connections = []
        if NETWORK_GRAPH.nodes[node]['node_type'] == "Router":
            if list(NETWORK_GRAPH.out_edges(node)):
                for connection in list(NETWORK_GRAPH.out_edges(node)):
                    if "sw" in connection[1]:
                        continue
                    
                    connections.append(NETWORK_GRAPH.edges[connection]['right_end']['ip'])
                    
            
            if list(NETWORK_GRAPH.in_edges(node)):
                for connection in list(NETWORK_GRAPH.in_edges(node)):
                    if "sw" in connection[0] or "h" in connection[0]:
                        continue
                    
                    connections.append(NETWORK_GRAPH.edges[connection]['left_end']['ip'])

            #
            for interface in NETWORK_GRAPH.nodes[node]['network_interfaces']:
                if interface.nat == 'enabled':
                    connections.append(interface.public_ip.split("/")[0])
                else:
                    connections.append(str(interface.ip))
            
            # Add found connections as an attribute to the node
            NETWORK_GRAPH.nodes[node]['connections'] = connections
            
            
            

        #print(f" Node:{node}, edges: {NETWORK_GRAPH.in_edges + list(NETWORK_GRAPH.out_edges(node))}")


def if_config() -> None: 
    # Shows every interface
    
    for node in NETWORK_GRAPH.nodes:
        for interface in NETWORK_GRAPH.nodes[node]['network_interfaces']:
            print(f"Node: {node}, Type: {NETWORK_GRAPH.nodes[node]['node_type']}  \n{interface.__str__()}\n")
            
            
def create_subnet_mac_table(subnet: nx.DiGraph) -> pd.DataFrame:
    """ Create a table for every mac address there is in a given subnet """
    
    mac_table_dict = {"Node": [], "mac": []} 
    for node in subnet:
        if subnet.nodes[node]['node_type'] != "Hub":    #No mac for hub
            for interfac in subnet.nodes[node]['network_interfaces']:
                mac_table_dict["Node"].append(node)
                mac_table_dict["mac"].append(str(interfac.mac))

    return pd.DataFrame(mac_table_dict)


def create_router_addresses_table() -> dict:
    """ Dictionary that contains every routing table and its addresses
        i.e router_addresses = {'30.2.0.1' : 'r1', '40.2.0.1' : 'r2'}
    """
    
    router_addresses = {}

    for node in NETWORK_GRAPH:
        if NETWORK_GRAPH.nodes[node]['node_type'] == "Router":
            for interface in NETWORK_GRAPH.nodes[node]['network_interfaces']:
                if interface.nat == 'enabled':
                    router_addresses[str(interface.public_ip.split("/")[0])] = node
                else:
                    router_addresses[str(interface.ip)] = node
    
    NETWORK_GRAPH.router_addresses = router_addresses
    # print(f"Router addresses: {router_addresses} \n\n")


def create_subnet_ip_table(subnet: nx.DiGraph) -> pd.DataFrame:
    """ Create a table for every ip address there is in a given subnet """
    
    ip_table_dict = {"Node": [], "ip": []}

    for node in subnet.nodes:
        if subnet.nodes[node]['node_type'] in ["Client_PC", "Server_PC", "Router"]:
            for interface in subnet.nodes[node]['network_interfaces']:
                ip_table_dict["Node"].append(node)
                ip_table_dict["ip"].append(str(interface.ip))
            

    return pd.DataFrame(ip_table_dict)


def find_subnets() -> list:
    """ Finds subnets in a given network """
    
    temp_subnets = []
    routers = []
    subnets = []
    

    # Finds physical subnets by removing router nodes
    G3 = NETWORK_GRAPH.copy()

    for node in list(G3.nodes): 
        if G3.nodes[node]['node_type'] == 'Router':
            routers.append(node)
            G3.remove_node(node)

    temp_subnets = [G3.subgraph(n) for n in nx.weakly_connected_components(G3)]

    # For every subnet found, going though NETWORK_GRAPH'S edges to find
    # current subnets router-gateway
    for sub in temp_subnets:
        subnet = sub.copy()
        for node in sub.nodes:
            for router in routers:
                
                # Checking if the current subnets node is connected with any one of the routers
                for end, my_node in zip(['right_end', 'left_end'], [(node, router), (router, node)]):
                    from_node, to_node = my_node
                    if NETWORK_GRAPH.has_edge(from_node, to_node):
                        
                        mask = NETWORK_GRAPH.edges[from_node, to_node][end]["mask"]
                        nat_enabled = NETWORK_GRAPH.edges[from_node, to_node][end]["nat"] == 'enabled'
                        gateway = NETWORK_GRAPH.edges[from_node, to_node][end]["ip"]
                        
                        if nat_enabled:
                            subnet_address = NETWORK_GRAPH.edges[from_node, to_node][end]["public_ip"].split('/')[0]
                        else : 
                            subnet_address = NETWORK_GRAPH.edges[from_node, to_node][end]["ip"]

                        router_interface = [nif.RouterInterface(NETWORK_GRAPH.edges[from_node, to_node][end])]
                        subnet.add_nodes_from([(router, {'node_type' : 'Router', 'routing_table' : NETWORK_GRAPH.nodes[router]['routing_table'], 'network_interfaces' : router_interface})])
                        subnet.add_edges_from([(from_node, to_node, NETWORK_GRAPH.edges[from_node, to_node])])

        # Checking if subnets router is found
        if not any(subnet.nodes[node]['node_type'] == 'Router' for node in subnet):
            print("Found subnet without a router")
            exit(0)
    
        # Adding Subnet's attributes as graph attributes
        subnet.nat_enabled = nat_enabled    # Must be added before creating ip table
        subnet.mac_table = create_subnet_mac_table(subnet)
        subnet.ip_table = create_subnet_ip_table(subnet)
        subnet.gateway = IPAddress(gateway)
        subnet.mask = IPAddress(mask)
        subnet.subnet_address = subnet_address 
        subnets.append(subnet)

    return subnets    


def is_unique_mac(subnet: nx.DiGraph) -> None:
    """ Checks if there are any duplibate mac addresses in a given subnet"""

    global found_error 
    
    # Dataframe with all the duplicate mac addresses -empty if none duplicate exists-
    duplicate_mac_df = subnet.mac_table[subnet.mac_table.duplicated(["mac"], keep = False)]    
    if not duplicate_mac_df.empty:
        print(f"Found duplicate mac addresses at subnet {str(subnet.gateway)}/{str(subnet.mask.netmask_bits())}: \n{duplicate_mac_df.to_string(index=False)}\n")
        found_error = True


def is_unique_subnet(subnets) -> None:
    """ Checks if a subnet is unique"""
    
    subnet_addr_list = []
    for subnet in subnets:
        subnet_addr_list.append(str(subnet.subnet_address) + '/' + str(subnet.mask.netmask_bits()))

    subnets_df = pd.DataFrame(subnet_addr_list, columns = ['Subnets'])
    duplicate_subents_df = subnets_df[subnets_df.duplicated(['Subnets'], keep = False)]
    
    # If the dataframe is not empty means there are duplicate values
    if not duplicate_subents_df.empty:
        print(f"Found dublicate subnets:\n {duplicate_subents_df}\n")
        print("Network validation has ended!")
        exit()


def is_unique_subnet_ip(subnet: nx.DiGraph) -> None:
    """Checks if the ip addresses of the subnet are unique"""
    
    global found_error
    ip_table_df = subnet.ip_table
    duplicate_ip_df = ip_table_df[ip_table_df.duplicated(["ip"], keep = False)]
    
    if not duplicate_ip_df.empty:
        found_error = True
        print(f"-Found duplicate ip addresses at subnet {str(subnet.gateway)}/{str(subnet.mask.netmask_bits())}: \n{duplicate_ip_df.to_string(index=False)}\n")


def ip_belongs_at_subnet(subnet: nx.DiGraph) -> None:
    """ 
    Checks if an ip address belongs at its subnet
    Find nodes gateway, see if it matches subnets gateway
    and see if nodes ip belongs at subnet
    """
    
    global found_error
    for node in subnet:
        if subnet.nodes[node]['node_type'] not in ['Switch', 'Hub', 'Router']:
            for i in range(len(subnet.nodes[node]['network_interfaces'])):                    
                nodes_gateway_address = subnet.nodes[node]['network_interfaces'][i].gateway
                
                # Checks if subnets gateway matches each nodes gateway
                if subnet.gateway != nodes_gateway_address:
                    found_error = True
                    print(f"-Gateway error at {node}:\n{TAB}{TAB}Subnets Gateway: {subnet.gateway},\n{TAB}{TAB}{node} gateway {nodes_gateway_address}\n")    
                
                ip_address = subnet.nodes[node]['network_interfaces'][i].ip
                subnet_mask = '/' + str(subnet.nodes[node]['network_interfaces'][i].mask.netmask_bits())
                
                # ip belongs at its subnet
                if ip_address not in IPNetwork(str(subnet.gateway) + subnet_mask):
                    found_error = True
                    print(f"-{node}'s ip address: {str(ip_address)}  does not belong at its subnet {str(subnet.gateway) + subnet_mask}\n")         


def is_connected_to(router_id: str, next_hop: str) -> bool:
    return next_hop in NETWORK_GRAPH.nodes[router_id]['connections']


def validate_routing_table_entries() -> None:
    """ Checks for duplicate destination entries in routing tables"""
    
    found_duplicate = False
    for node in NETWORK_GRAPH.nodes:
        if NETWORK_GRAPH.nodes[node]['node_type'] == 'Router':
            routing_table = NETWORK_GRAPH.nodes[node]['routing_table']
            duplicate_dest_df = routing_table[routing_table.duplicated(["dest"], keep = False)]    
            if not duplicate_dest_df.empty:
                print(f"Found duplicate destination entries at \n{routing_table}\n")
                found_duplicate = True
    
    # Found duplicate destination entries in routing tables
    if found_duplicate:
        print("Duplicate entries at routing tables, network validation has ended!")
        exit(0)


def validate_routes(subnets: list) -> None:
    """
    Validates the routes beetween the subnets
    """

    error_found = False

    # Sender subnet
    for sender_sub in subnets:
        senders_addr= sender_sub.subnet_address
        senders_mask = sender_sub.mask
 
        # Destination subnet
        for dest_sub in subnets:
            
            # Same subnet
            if senders_addr ==  dest_sub.subnet_address:
                continue
            
            router_id = NETWORK_GRAPH.router_addresses[senders_addr]
            routing_table = NETWORK_GRAPH.nodes[router_id]["routing_table"]
            
            destinations_addr = dest_sub.subnet_address
            destinations_mask = dest_sub.mask
            routing_path = [senders_addr]
            dest_found = False
            loop_found = False
            max_jumps = 20
            jumps_counter = 0
            
            # Jumping from routing table to another until destination is found or loop is found
            # or maximum number of jumps exceeded-meaning that something went wrong 
            while(not(dest_found or loop_found) and jumps_counter <= max_jumps):
                jumps_counter += 1
                dest_entry_in_rt = False
                dest_entry_value = 0 
               
                # Checks if there is an entry for destination in routing table
                for index, dest_entry in enumerate(list(routing_table['dest'])):
                    mask = str(IPAddress(routing_table['mask'][index]).netmask_bits())
                    if destinations_addr in IPNetwork(dest_entry + "/" + mask):
                        dest_entry_value = dest_entry
                        dest_entry_in_rt = True

                # If destination entry found in routing table, find destinations next hop
                if dest_entry_in_rt:        
                    next_hop = routing_table.loc[routing_table['dest'] == dest_entry_value].next_hop.values[0]
                    
                    # Check that there is a connection-link-edge between the current router and the next_hop
                    if not is_connected_to(router_id, next_hop):
                        error_found = True
                        print(f"Found error at connections!")
                        print(f"Router {router_id} has no connection with interface with addresss {next_hop}\n")
                        break
                    
                    # If the next hop already exists in the routing path
                    # it means we have found a loop 
                    if next_hop in routing_path and next_hop != dest_entry:
                        routing_path.append(next_hop)
                        loop_found = True
                        break 
                    else:
                        routing_path.append(next_hop)

                    # Destination network found
                    if destinations_addr in IPNetwork(next_hop + "/" + str(destinations_mask.netmask_bits())):
                        dest_found = True
            
                else:
                    # Did not find any entry for the destination in routing table
                    # Take as next hop the routing tables default route-gateway 
                    if "0.0.0.0" in list(routing_table.dest):
                        next_hop = routing_table.loc[routing_table['dest'] == "0.0.0.0"].next_hop.values[0]
                         
                         # Check that there is a connection-link-edge between the current router and the next_hop
                        if not is_connected_to(router_id, next_hop):
                            error_found = True
                            print("Found error at connection")
                            print(f"Router {router_id} has no connection with an interface with addresss {next_hop}\n")
                            break
                    
                    else:
                        # No default gateway for the routing table
                        print(f"Did not find entry or default route from {senders_addr} to {destinations_addr} on the routing table!")
                        exit()

                # Jump to the next router-routing table
                router_id = NETWORK_GRAPH.router_addresses[next_hop]
                routing_table = NETWORK_GRAPH.nodes[router_id]["routing_table"]

            

            #print(f"From subnet: {senders_addr}/{senders_mask.netmask_bits()}, to subnet {destinations_addr}/{destinations_mask.netmask_bits()}") 
            node_path = list(set([NETWORK_GRAPH.router_addresses[addr] for addr in routing_path]))
            
            if dest_found:
                #print(f"Destination found, path: {routing_path}\n\n")
                pass

            if loop_found:
                error_found = True
                print(f"Found loop in routing path from: {senders_addr}, to {destinations_addr}\n\n")
            
            if jumps_counter > max_jumps:
                error_found = True
                print(f"Maximum number of jumps exceeded, something went wrong!\n")

    if error_found:
        print("Found errors at routing tables, network validation has ended!\n")
        exit()
    else: 
        print("Routing table validation completed!\n")


def validate_routing_tables(subnets: list) -> None:
    
    # First check that there is no duplicate destination entries in the routing tables
    validate_routing_table_entries()
    
    # Procceed to route validation if only no error at network is found
    validate_routes(subnets)


def validate_subnets(network_subnets: list) -> None:
    """
    Through subnet validation we make sure that:
        - Every subnet is unique unless NAT
        - Every mac address in a subnet is unique
        - Every node in a subnet has the right gateway 
        - Every ip address in a subnet belongs at its subnet
        - Every ip address in a subnet is unique
    """
    # First, checking if each subnet is unique
    # If not, validation stops here
    is_unique_subnet(network_subnets)
    
    for subnet in network_subnets:
       
        # mac address in a network is unique
        is_unique_mac(subnet)
        
        # ip address in a subnet belongs at its subnet
        ip_belongs_at_subnet(subnet)
        
        # ip address in a subnet is unique
        is_unique_subnet_ip(subnet)
    
    # Found error at configurations, validation ends here 
    if found_error:
        print("Found configuration errors. Network validation has ended!")
        exit(0)
    else:
        print("Subnet validation completed!\n")


def init_visualization(path: str, filename: str):
    """ Visualization initialization
        
        Available aesthetic profiles:
            2D 
                -black_and_white
                -soft_dark
                -total_dark
                -neon_dark
                -classic_blue
                -light_grey_black
                -light_grey_white
                -light_grey_blue
            3D
                # TODO
    """
    
    theme_option = "neon_dark"

    #Load visualization theme configuration file
    with open("vis_themes.yml", 'r') as cf:		
       
        try:
            vis_theme = yaml.load(cf, Loader = yaml.FullLoader)
        except yaml.YAMLError as exc:
            print(exc)

    
    renderer = rd.Renderer(NETWORK_GRAPH, HELP_NET_GRAPH, vis_theme[theme_option], filename.split('.')[0], path)
    renderer.render()


#Main funtion
def main(example: str) -> None:
    
    example_no = example.split("_")[1]
    filename = f"net_topology_{example_no}.tgf"

    # Find file in currrent directory
    path = find_path(filename, example)    
    
    # Parse netowork
    parse_network(path, filename)
    
    # Render the network topology
    init_visualization(path, filename)

    # Find network subnets
    #network_subnets = find_subnets()
    
    # Validate subnets
    #validate_subnets(network_subnets)
    
    # Validate routing tables
    #validate_routing_tables(network_subnets)
    
    #Show every network interface on the network
    #if_config()

    print("Network validation completed!")


def start_network_validation(example: str) -> None:
    """ The function/interface that is called from the controller"""
    
    main(example)


if __name__ == '__main__':
    print("Warning: This file is called from the main controller, doesnt run on its own!")
    
    
    


  
