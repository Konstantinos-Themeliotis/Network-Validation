""" Network validation 

    This file is responsible for the process of network validation.

"""

#Imports
import netaddr
import networkx as nx
import ast
from netaddr import *
import os.path
import pandas as pd
from pandas.core.reshape.concat import concat
import tgf_parser as tgf
import network_renderer as rd
import network_interface as nif


# Global variables
NETWORK_GRAPH = nx.DiGraph()    #network topology graph
HELP_NET_GRAPH = nx.DiGraph()   #help graph used for visualization

# TAB char for printing messages
TAB = "    "


def print_err_and_exit():
    """ Prints error message and terminates network validation process"""

    print("Found network configuration errors. Network validation has ended!")
    exit(0)


def find_path(filename: str, topology: str) -> str:
    """ Returns current toplogy directory, if not found network validation terminates """
    
    current_directory_path = os.path.dirname(os.path.realpath(__file__))
    examples_directory = current_directory_path + "\\" + "topologies" + "\\" + topology
    if filename not in os.listdir(examples_directory):
        print(f"-File Error: File '{filename}' does not exist in current directory\n")
        exit(0)

    return examples_directory


def parse_network(path: str, filename: str) -> None:
    """ Parses the configurated network topology.
    
        Parses the configurated network topology using the 'tgf_parser'
        and calls the init function to initialize the graph    
    """ 
    
    parser = tgf.Init_TGF_Parser(path, filename)
    nodes, edges = parser.parse_network_topology()
    init_graphs(nodes, edges)


def init_graphs(nodes: list, edges: list):
    """ Initializes graphs 

    Creates the NetworkX graph object representing the network topology
    using the parsed tgf file. It also creates a secondary help graph object.  
    
    Note: It would be better to create routing table Dataframes while parsing
    and add them directly as attributes to the graph. But pyvis can not handle them.
    So the NETWORK_GRAPH is first created simply, and then adds the objects as attributes
    
    """
    
    # Creating Networkx Graph
    NETWORK_GRAPH.add_nodes_from(nodes)
    NETWORK_GRAPH.add_edges_from(edges)
    HELP_NET_GRAPH.add_nodes_from(nodes)
    HELP_NET_GRAPH.add_edges_from(edges)

    # Set 'network_interaces' as an attribute at each node.
    # 'network_interfaces is a list containing each nodes network interfaces
    for node in NETWORK_GRAPH.nodes:
        NETWORK_GRAPH.nodes[node]["network_interfaces"] = []    

    # Initialize interfaces with the data from dge attributes
    create_interfaces()

    # Creating routing table dataframes for every Router
    for node in NETWORK_GRAPH:
        if NETWORK_GRAPH.nodes[node]['node_type'] == 'Router':
            routing_table = pd.DataFrame(NETWORK_GRAPH.nodes[node]['routing_table'])
            NETWORK_GRAPH.nodes[node]['routing_table'] = routing_table    
    
    # Router addresses table
    create_router_addresses_table()
    
    # Find every routers -and in the future (refactoring) every nodes- connection
    # Needed for route validation
    find_router_connections()


def create_interfaces() -> None:
    """ Creates the network interface objects from graph's edge attributes 
        
        -Scans through networks edges attributes to extract  
        every different network interfaces, creates network interface objects 
        and adds them to each node, at network_interfaces field 

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

            # The -not in- is based on the __eq__() func in the network interface class 
            if interface not in NETWORK_GRAPH.nodes[edge[index]]['network_interfaces']:
                NETWORK_GRAPH.nodes[edge[index]]['network_interfaces'].append(interface)
            elif node_type in {'Client_PC', 'Server_PC'}: 
                print(f"Warning: Duplicate network interface found on {edge[index]}")


def find_router_connections() -> None:
    """ Founds router connections

        For each router, scans through network to find its connections/edges/link
        
        Notice:
            NOT a good function, refactoring needed above for a better solution,
            but for now it must be implemented for routing to work 

    """

    for node in NETWORK_GRAPH.nodes:

        connections = []
        
        # Searching for every Routers connections with: Client_PC, Server_PC or Router
        if NETWORK_GRAPH.nodes[node]['node_type'] == "Router":
            
            # First checks the out connections - if true, out edges exist
            if list(NETWORK_GRAPH.out_edges(node)):
                for edge_connection in list(NETWORK_GRAPH.out_edges(node)):
                    
                    # The first element of edge_connection is the out node 
                    if "sw" in edge_connection[1] or "h" in edge_connection[1]:
                        continue
                    
                    connections.append(NETWORK_GRAPH.edges[edge_connection]['right_end']['ip'])
                    
            # Second checks for in connections - if true, in edges exist
            if list(NETWORK_GRAPH.in_edges(node)):
                for edge_connection in list(NETWORK_GRAPH.in_edges(node)):

                    # The second element of edge_connection is the in node
                    if "sw" in edge_connection[0] or "h" in edge_connection[0]:
                        continue
                    
                    connections.append(NETWORK_GRAPH.edges[edge_connection]['left_end']['ip'])

            # Adding the currents router interface at its connections - a router obv is connected at itself
            for interface in NETWORK_GRAPH.nodes[node]['network_interfaces']:
                if interface.nat == 'enabled':
                    connections.append(str(interface.public_ip))
                else:
                    connections.append(str(interface.ip))
            
            # Add found connections as an attribute to the node
            NETWORK_GRAPH.nodes[node]['connections'] = connections
            

def create_router_addresses_table() -> dict:
    """ Dictionary that contains every routers public addresses
        
        i.e router_addresses = {'30.2.0.1' : 'r1', '40.2.0.1' : 'r2'}
        Used in routing to find witch the next_hop router is
    """
    
    router_addresses = {}

    for node in NETWORK_GRAPH:
        if NETWORK_GRAPH.nodes[node]['node_type'] == "Router":
            for interface in NETWORK_GRAPH.nodes[node]['network_interfaces']:
                if interface.nat == 'enabled':
                    router_addresses[str(interface.public_ip)] = node
                else:
                    router_addresses[str(interface.ip)] = node
    
    NETWORK_GRAPH.router_addresses = router_addresses

           
def create_subnets_mac_table(subnet: nx.DiGraph) -> pd.DataFrame:
    """ Creates a table that contains every mac address in a given subnet """
    
    mac_table_dict = {"Node": [], "Interface": [], "MAC_Address": []} 
    for node in subnet:
        if subnet.nodes[node]['node_type'] != "Hub":    #No mac for hub
            for interface in subnet.nodes[node]['network_interfaces']:
                mac_table_dict["Node"].append(node)
                mac_table_dict["Interface"].append(str(interface.if_id))
                mac_table_dict["MAC_Address"].append(str(interface.mac))

    return pd.DataFrame(mac_table_dict)


def create_subnets_ip_table(subnet: nx.DiGraph) -> pd.DataFrame:
    """ Create a table which contains every ip address there is in a given subnet """
    
    ip_table_dict = {"Node": [], "Interface" : [],"IP_Address": []}

    for node in subnet.nodes:
        if subnet.nodes[node]['node_type'] in ["Client_PC", "Server_PC", "Router"]:
            for interface in subnet.nodes[node]['network_interfaces']:
                ip_table_dict["Node"].append(node)
                ip_table_dict["Interface"].append(interface.if_id)
                ip_table_dict["IP_Address"].append(str(interface.ip))
            

    return pd.DataFrame(ip_table_dict)


def find_subnets() -> tuple:
    """ Finds physical and router subnets.

        Scan though the network graph to find the subnets. 
        Adds them as an attribute to the network graph object

        -A physical subnet is a subnet that the devices connected at it need 
        no router to communicate.
        
        -A router subnet is the subnet that the two connected routers belongs to

    
    """
    
    router_subnets = []
    physical_subnets = []
    
    def find_physical_subnets():
        """ Finds the physical subnet of the network
        
        -To find a physical subnet, remove every router from the network graph,
        the remaing connected devices belong at the same subnet  

        """
        temp_subnets = []
        routers = []
    
        G3 = NETWORK_GRAPH.copy()

        # Finds physical subnets by removing router nodes
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
                            host_router_id = router
                            gateway = IPAddress(NETWORK_GRAPH.edges[from_node, to_node][end]["ip"])
                            mask = IPAddress(NETWORK_GRAPH.edges[from_node, to_node][end]["mask"])
                            nat = NETWORK_GRAPH.edges[from_node, to_node][end]["nat"]
                            
                            if nat == 'enabled':
                                address = NETWORK_GRAPH.edges[from_node, to_node][end]["public_ip"].split('/')[0]
                                private_address = NETWORK_GRAPH.edges[from_node, to_node][end]["ip"]
                            else : 
                                address = NETWORK_GRAPH.edges[from_node, to_node][end]["ip"]
                                private_address = "0.0.0.0"

                            router_interface = [nif.RouterInterface(NETWORK_GRAPH.edges[from_node, to_node][end])]
                            subnet.add_nodes_from([(router, {'node_type' : 'Router', 'routing_table' : NETWORK_GRAPH.nodes[router]['routing_table'], 'network_interfaces' : router_interface})])
                            subnet.add_edges_from([(from_node, to_node, NETWORK_GRAPH.edges[from_node, to_node])])

            # Checking if subnets router is found
            if not any(subnet.nodes[node]['node_type'] == 'Router' for node in subnet):
                print("Subnet Error: Found subnet without a router")
                print_err_and_exit()
        
            # Adding Subnet's attributes as graph attributes
            subnet.nat = nat   # Must be added before creating ip table           
            subnet.private_address = IPNetwork(f"{private_address}/{mask.netmask_bits()}")
            subnet.host_router_id = host_router_id
            subnet.mac_table = create_subnets_mac_table(subnet)
            subnet.ip_table = create_subnets_ip_table(subnet)
            subnet.gateway = IPAddress(gateway)
            subnet.mask = IPAddress(mask)
            subnet.subnets_address = IPNetwork(f"{address}/{mask.netmask_bits()}")
            physical_subnets.append(subnet)


    def find_router_subnets():
        """ Find the subnets between the routers
        
        A router subnet is the subnet that the two connected routers belongs to
        """

        found_ip_error = False        
        for edge in NETWORK_GRAPH.edges:
            left_end_type = NETWORK_GRAPH.nodes[edge[0]]['node_type']
            right_end_type = NETWORK_GRAPH.nodes[edge[1]]['node_type']
            
            # Link between routers
            if left_end_type == "Router" and right_end_type == "Router":
                left_end_ip = IPAddress(NETWORK_GRAPH.edges[edge]['left_end']['ip'])
                left_end_mask = IPAddress(NETWORK_GRAPH.edges[edge]['left_end']['mask']).netmask_bits()
                left_end_subnet = IPNetwork(f"{left_end_ip}/{left_end_mask}")
                left_end_inteface = NETWORK_GRAPH.edges[edge]['left_end']['if_id']
                
                right_end_ip = IPAddress(NETWORK_GRAPH.edges[edge]['right_end']['ip'])
                right_end_mask = IPAddress(NETWORK_GRAPH.edges[edge]['right_end']['mask']).netmask_bits()
                right_end_subnet = IPNetwork(f"{right_end_ip}/{right_end_mask}")
                right_end_inteface = NETWORK_GRAPH.edges[edge]['right_end']['if_id']



                if left_end_subnet != right_end_subnet:
                    print(f"-Router link IP Error:\n{TAB} Nodes: {edge[0]}, interface: {left_end_inteface}, IP: {left_end_ip}/{left_end_mask} and\n",
                            f"{TAB}Nodes: {edge[1]}, interface {right_end_inteface}, IP: {right_end_ip}/{right_end_mask} at link with ID: '{NETWORK_GRAPH.edges[edge]['link_ID']}'\n", 
                            f"does not belong to the same subnet! \n")
                    found_ip_error = True
                else:
                    router_subnets.append((f"{edge[0]} {edge[1]}", str(right_end_subnet.cidr)))   
        
        if found_ip_error:
            print_err_and_exit()


    def create_networks_subnet_table() -> None:
        """ Create a networks subnets table.

        Creates a table (pandas dataframe) that contains every subnet address in 
        the network. The address table is added to the graph as an attribute

        """
        
        physical_subnet_dict = {"Host_Router_ID": [], "Address": []} 
        router_subnet_dict = {"Router_ID": [], "Address": []}
        public_subnet_dict = {"Host_Router_ID": [], "Address": []}

        # Adding physical subnets to the list
        for subnet in physical_subnets:
                physical_subnet_dict['Host_Router_ID'].append(subnet.host_router_id)
                physical_subnet_dict['Address'].append(str(subnet.subnets_address.cidr))

        for p_subnet in physical_subnets:
            if p_subnet.nat == 'disabled':
                public_subnet_dict['Host_Router_ID'].append(subnet.host_router_id)
                public_subnet_dict['Address'].append(str(subnet.subnets_address.cidr))

            
        for r_subnet in router_subnets:
            router_subnet_dict['Router_ID'].append(r_subnet[0])
            router_subnet_dict["Address"].append(r_subnet[1])

        # Adding subnets between routers to the list
        #subnet_addr_list += router_subnets 
        
        NETWORK_GRAPH.physical_subnets_addr = pd.DataFrame(physical_subnet_dict)
        NETWORK_GRAPH.public_subnets_addr = pd.DataFrame(physical_subnet_dict)
        NETWORK_GRAPH.router_subnets_addr = pd.DataFrame(router_subnet_dict)
    
    # First find the physical subnets of the network
    find_physical_subnets()

    # Second find the router subnets
    find_router_subnets()
    
    # Create a subnet table that contains every subnet in the network 
    create_networks_subnet_table()

    # Only physical subnets needs to be returned
    return physical_subnets    


def validate_mac(subnets: list) -> bool:
    """ Checks for duplicate mac addresses"""
    
    is_valid_mac = True
    
    def is_unique_subnet_mac():
        """ Checks for duplicate mac addresses in a subnet"""
        
        nonlocal is_valid_mac
        for subnet in subnets:
            # Dataframe with all the duplicate mac addresses -empty if none duplicate exists-
            duplicate_mac_df = subnet.mac_table[subnet.mac_table.duplicated(["MAC_Address"], keep = False)]    
            if not duplicate_mac_df.empty:
                
                if subnet.nat == 'enabled':
                    subnets_address = subnet.private_address.cidr
                else:
                    subnets_address = subnet.subnets_address.cidr
                
                print(f"-MAC Address Error: Found duplicate MAC addresses at subnet {subnets_address},", 
                    f"host router {subnet.host_router_id}: \n{duplicate_mac_df.to_string(index=False)}\n")
                is_valid_mac =  False


    def is_unique_router_mac():
        """ Checks if every routers interfaces have unique mac addressess"""
        
        nonlocal is_valid_mac
        for node in NETWORK_GRAPH.nodes:
            mac_addr_dict = {"Interface" : [], "MAC_Address": []}
            if NETWORK_GRAPH.nodes[node]['node_type'] == 'Router':
                for interface in NETWORK_GRAPH.nodes[node]['network_interfaces']:
                    mac_addr_dict['Interface'].append(interface.if_id)
                    mac_addr_dict["MAC_Address"].append(interface.mac)
                
                mac_addr_df = pd.DataFrame(mac_addr_dict)
                duplicate_mac_df = mac_addr_df[mac_addr_df.duplicated(["MAC_Address"], keep = False)]
                
                if not duplicate_mac_df.empty:
                    print(f"-MAC Address Error: Found duplicate MAC addresses at routers {node} interfaces,", 
                        f"\n{duplicate_mac_df.to_string(index=False)}\n")
                    is_valid_mac = False
    

    def is_unique_router_link_mac():
        """ Checks if mac addresses in a link between two routers is unique"""
       
        nonlocal is_valid_mac
        for edge in NETWORK_GRAPH.edges:
            left_end_node, right_end_node = edge
            left_end_node_type = NETWORK_GRAPH.nodes[left_end_node]['node_type']
            right_end_node_type = NETWORK_GRAPH.nodes[right_end_node]['node_type']
            
            if left_end_node_type == right_end_node_type == "Router":
                left_end_mac = NETWORK_GRAPH.edges[edge]['left_end']['mac']
                right_end_mac = NETWORK_GRAPH.edges[edge]['right_end']['mac']
                if left_end_mac == right_end_mac:
                    print(f"-MAC Address Error: Found duplicate MAC addresses at link between routers with link ID: {NETWORK_GRAPH.edges[edge]['link_ID']}\n",
                        f"Node{TAB}Interface{TAB}MAC_Address\n",
                        f" {left_end_node}{TAB}  {NETWORK_GRAPH.edges[edge]['left_end']['if_id']}{TAB}    {left_end_mac}\n",
                        f" {right_end_node}{TAB}  {NETWORK_GRAPH.edges[edge]['right_end']['if_id']}{TAB}    {right_end_mac}\n")
                    is_valid_mac = False

    is_unique_subnet_mac()
    is_unique_router_mac()
    is_unique_router_link_mac()
    
    return is_valid_mac


def is_unique_router_con_ip() -> bool:
    """ Checks if ip between router connection are unique"""

    is_unique_ip = True
    for edge in NETWORK_GRAPH.edges:
        left_end_type = NETWORK_GRAPH.nodes[edge[0]]['node_type']
        right_end_type = NETWORK_GRAPH.nodes[edge[1]]['node_type']
        link_id = NETWORK_GRAPH.edges[edge]['link_ID']
        
        # Link between routers
        if left_end_type == "Router" and right_end_type == "Router":
            left_end_ip = IPAddress(NETWORK_GRAPH.edges[edge]['left_end']['ip'])
            left_end_inteface = NETWORK_GRAPH.edges[edge]['left_end']['if_id']
            
            right_end_ip = IPAddress(NETWORK_GRAPH.edges[edge]['right_end']['ip'])
            right_end_inteface = NETWORK_GRAPH.edges[edge]['right_end']['if_id']
        
            if left_end_ip == right_end_ip:
                is_unique_ip = False
                print("-IP Address Error: Found duplicate IP address between router connections:")
                print(f"{TAB}Connection: {str(edge)}, link ID: {link_id}\n{TAB}{edge[0]} interface: {left_end_inteface}, IP: {left_end_ip}\n{TAB}{edge[1]} interface: {right_end_inteface}, IP: {right_end_ip}\n")
    
    return is_unique_ip


def is_unique_subnet() -> bool:
    """ Checks if subnets are unique """

    unique_subnets = True
    
    # Subnets found on the network
    public_subnets_df = NETWORK_GRAPH.physical_subnets_addr
    router_subnets_df = NETWORK_GRAPH.router_subnets_addr
    
    def is_unique_public_subnet() -> None:
        """ Checks for duplicate physical subnets """
        nonlocal unique_subnets
        duplicate_public_sub_df = public_subnets_df[public_subnets_df.duplicated(["Address"], keep = False)]    
        if not duplicate_public_sub_df.empty:
            print(f"Subnet error: Found duplicate subnets:\n{duplicate_public_sub_df.to_string(index=False)}\n")
            unique_subnets = False
        

    def is_unique_router_subnet() -> None:
        """ Checks for duplicate router subnets"""
        nonlocal unique_subnets
        duplicate_router_sub_df = router_subnets_df[router_subnets_df.duplicated(["Address"], keep = False)]    
        if not duplicate_router_sub_df.empty:
            print(f"Subnet error: Found duplicate subnets between routers:\n{duplicate_router_sub_df.to_string(index=False)}\n")
            unique_subnets = False

        
    is_unique_public_subnet()
    is_unique_router_subnet()
        
    # Check for duplicate in the whole network only if none
    # duplicate, physical or router subnet is found previously
    #if unique_subnets:
        #is_unique_net_subnets()
    

    return unique_subnets
                       

def is_valid_ip_subnet(subnet: nx.DiGraph) -> bool:
    """ Validates that a IP subnet is correctly configurated"""

    is_valid_ip = True


    def ip_belongs_at_subnet() -> bool:
        """ Checks if gateways and ip address are valid
        
            Validates that in each network interface that:
            
                -The gateway matches subnets gateway
                -IP address belongs at network
        """
        
        ip_belongs_subnet = True
        for node in subnet:
            if subnet.nodes[node]['node_type'] in {"Client_PC", "Server_PC"}:
                for interface in subnet.nodes[node]['network_interfaces']:                    
                    nodes_gateway_address = interface.gateway
                     
                    if subnet.nat == 'enabled':
                        subnets_address = subnet.private_address.cidr
                    else :
                        subnets_address = subnet.subnets_address.cidr
                    
                    # Checks if subnets gateway matches each nodes gateway
                    if subnet.gateway != nodes_gateway_address:

                        ip_belongs_subnet = False
                        print(f"-Gateway error: Invalid gateway at node '{node}', interface: '{interface.if_id}',", 
                            f"subnet: {subnets_address}, host router: {subnet.host_router_id}")
                        print(f"{TAB}-Subnets Gateway: '{subnet.gateway}'\n{TAB}-{node} gateway '{nodes_gateway_address}'\n")    
                        continue
                    
                    ip_address = interface.ip
                    subnet_mask = '/' + str(interface.mask.netmask_bits())
                    
                    # Checks if ip belongs at subnet
                    if ip_address not in IPNetwork(str(subnet.gateway) + subnet_mask):
                        ip_belongs_subnet = False
                        print(f"-IP Address Error:\n{TAB}Nodes '{node}', interface: '{interface.if_id}', IP Address: '{str(ip_address)}'",
                            f", does not belong to its subnet '{subnets_address}', host router: {subnet.host_router_id}\n")         

        return ip_belongs_subnet


    def is_unique_subnet_ip() -> bool:
        """Checks if the ip addresses of the subnet are unique"""
        
        ip_table_df = subnet.ip_table
        duplicate_ip_df = ip_table_df[ip_table_df.duplicated(["IP_Address"], keep = False)]

        if subnet.nat == 'enabled':
            subnets_address = subnet.private_address.cidr
        else :
            subnets_address = subnet.subnets_address.cidr

        if not duplicate_ip_df.empty:
            print(f"-IP Address Error: Found duplicate IP addresses at subnet:{subnets_address} with host router: {subnet.host_router_id}\n",
                f"{duplicate_ip_df.to_string(index=False)}\n")
            return False
        
        return True



    if not ip_belongs_at_subnet():
        is_valid_ip = False
    
    if not is_unique_subnet_ip():
        is_valid_ip = False
        
    return is_valid_ip


def validate_subnets(network_subnets: list) -> None:
    """ Calls processes to validate a  subnet

    Through subnet validation we make sure that:
        - Every subnet is unique unless NAT
        - Every mac address in a subnet is unique
        - Every node in a subnet has the right gateway 
        - Every ip address in a subnet belongs at its subnet
        - Every ip address in a subnet is unique

    """
    found_ip_error = False
   
    # First, checking if each subnet is unique
    # If not, validation stops here
    if not is_unique_subnet():
       print_err_and_exit()

    # Checking if ip in connection between routers are unique
    if not is_unique_router_con_ip():
        print_err_and_exit()
  
    # mac address in a network is unique
    if not validate_mac(network_subnets):
        print_err_and_exit()
       
    for subnet in network_subnets:
        if not is_valid_ip_subnet(subnet):
            found_ip_error = True
            
    if found_ip_error:
        print_err_and_exit()
       
    # Subnet validation completed sucefully
    print("Subnet validation completed!\n")


def validate_routing_tables(subnets: list) -> None:
    """ Start processes for routing table validation
    
        These processes:
            -Checks for duplicate destinations in a routing table
            -Validating the routes between subnets. That means that every
            node in a netowork can reach every other node.
    
    """

    def validate_routing_table_entries() -> None:
        """ Checks for duplicate destination entries in routing tables"""
        
        found_duplicate = False
        for node in NETWORK_GRAPH.nodes:
            if NETWORK_GRAPH.nodes[node]['node_type'] == 'Router':
                routing_table = NETWORK_GRAPH.nodes[node]['routing_table']
                duplicate_dest_df = routing_table[routing_table.duplicated(["dest"], keep = False)]    
                if not duplicate_dest_df.empty:
                    print(f"-Routing Table Validation Error:\nFound duplicate destination entries at routers {node}",
                    f"routing table \n{duplicate_dest_df.to_string(index=False)}\n")
                    found_duplicate = True
        
        # Found duplicate destination entries in routing tables
        if found_duplicate:
            print_err_and_exit()


    def validate_routes(subnets: list) -> None:
        """ Validates the routes beetween the subnets
        """
        
        def is_connected_to(router_id: str, next_hop: str) -> bool:
            """ Help function that checks if a router is connected with
                the next_hop in the routing table
            """
            return next_hop in NETWORK_GRAPH.nodes[router_id]['connections']


        error_found = False

        # Sender subnet
        for sender_sub in subnets:
            senders_addr = sender_sub.subnets_address
    
            # Destination subnet
            for dest_sub in subnets:
                
                # Same subnet
                if senders_addr ==  dest_sub.subnets_address:
                    continue
                
                router_id = NETWORK_GRAPH.router_addresses[str(senders_addr.ip)]
                routing_table = NETWORK_GRAPH.nodes[router_id]["routing_table"]
                
                destinations_addr = dest_sub.subnets_address
                destinations_mask = dest_sub.mask
                routing_path = [senders_addr]
                node_path = [router_id]
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

                    # If destinations entry found in routing table, find destinations next hop
                    if dest_entry_in_rt:        
                        next_hop = routing_table.loc[routing_table['dest'] == dest_entry_value].next_hop.values[0]
                        
                        # Check that there is a connection-link-edge between the current router and the next_hop
                        if not is_connected_to(router_id, next_hop):
                            error_found = True
                            print(f"Routing table validation Error:")
                            print(f"-Found error at router connections: Router {router_id} has no connection with an interface with IP addresss {next_hop}")
                            print(f"Route: From: '{senders_addr}', to: '{destinations_addr}'\n")
                            break
                        
                        # If the next hop already exists in the routing path
                        # it means that we already visited that node and 
                        # a loop is found 
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
                                print(f"Routing table validation Error:")
                                print(f"-Found error at router connections: Router {router_id} has no connection with an interface with IP addresss {next_hop}")
                                print(f"Route: From: '{senders_addr}', to: '{destinations_addr}'\n")
                                break
                        
                        else:
                            # No default gateway found for the routing table
                            print(f"Did not find entry or default route from {senders_addr} to {destinations_addr} on the routing table!")
                            exit()

                    # Jump to the next router-routing table
                    router_id = NETWORK_GRAPH.router_addresses[next_hop]
                    routing_table = NETWORK_GRAPH.nodes[router_id]["routing_table"]
                    node_path.append(router_id)

                # The route from sender to destination is valid
                if dest_found:
                    #print(f"Destination found, path: {node_path}\n\n")
                    pass
                
                # Found loop in the route between sender and destination
                if loop_found:
                    error_found = True
                    print(f"Routing table validation Error:")
                    print(f"{TAB}-Found loop in routing path from: '{senders_addr}', to: '{destinations_addr}'")
                    print(f"{TAB}-Node Router Path:", *node_path, sep = ' -> ')
                    print("\n")
                
                # Maximum number of jumps exceeded - something went wrong
                if jumps_counter > max_jumps:
                    error_found = True
                    print(f"Routing table validation Error:")
                    print(f"{TAB}-Maximum number of jumps exceeded, something went wrong!\n{TAB}From: {senders_addr}, to: {destinations_addr}\n")
                    
        # If a least one error is found, network validation
        # ends here unsuccesfull
        if error_found:
            print_err_and_exit()
        else: 
            print("Routing table validation completed!\n")


    # First check that there is no duplicate destination entries in the routing tables
    validate_routing_table_entries()
    
    # Procceed to route validation if only no error at network is found
    validate_routes(subnets)


def if_config() -> None: 
    """ Help function that shows every interface in the network"""
    
    for node in NETWORK_GRAPH.nodes:
        for interface in NETWORK_GRAPH.nodes[node]['network_interfaces']:
            print(f"Node: {node}, Type: {NETWORK_GRAPH.nodes[node]['node_type']}  \n{str(interface)}\n")


def init_visualization(path: str, filename: str):
    """ Visualization initialization
    
        Creates a Renderer object and passes the NetworkX graph to 
        handle the visualization process

    """
    
    renderer = rd.Renderer(NETWORK_GRAPH, HELP_NET_GRAPH, filename.split('.')[0], path)
    renderer.render()


#Main funtion
def main(topology: str) -> None:
    
    topology_no = topology.split("_")[1]
    filename = f"net_topology_{topology_no}.tgf"

    # Find file in currrent directory
    path = find_path(filename, topology)    
    
    # Parse netowork
    parse_network(path, filename)
    
    # Render the network topology
    init_visualization(path, filename)

    # Find network subnets 
    network_subnets = find_subnets()
        
    # # Validate subnets
    validate_subnets(network_subnets)
    
    # # Validate routing tables
    validate_routing_tables(network_subnets)


    print("Network validation completed!")


def start_network_validation(topology: str) -> None:
    """ The function/interface that is called from the controller"""
    
    main(topology)


if __name__ == '__main__':
    print("Warning: This file is called from the main controller, doesnt run on its own!")
    
