from netaddr import *
import yaml
import copy
import ast

#Constants
TAB = '    '

#Public variables
nodes = {}

#Different type of network interfaces #TODO client PC and Server PC have the same interface object
hub_interface = {'if_id' : ''}
switch_interface = {'if_id' : '', 'mac' : ''}
client_pc_interface = {'if_id' : '', 'mac' : '', 'ip' : '', 'mask' : '', 'gateway' : '', 'dns' : ''}
server_pc_interface = {'if_id' : '', 'mac' : '', 'ip' : '', 'mask' : '', 'gateway' : '', 'dns' : ''}
router_interface = {'if_id' : '', 'mac' : '', 'ip' : '', 'mask' : '', 'gateway' : '', 'dns' : '', 'nat' : ''}

node_type_interfaces = {'Hub' : hub_interface, 'Switch' : switch_interface, 'Router' : router_interface, 'Client_PC' : client_pc_interface, 'Server_PC' : server_pc_interface }

#link between nodes attributes
link = {'link_ID' : '', 'left_end' : '', 'right_end' : '', 'capacity' : '', 'latency' : ''}



def parse_net_config() -> dict:
    """ Parses the yaml network configuration file"""

    with open("net_config.yml", "r") as stream:
        try:
            data = yaml.load(stream, Loader=yaml.FullLoader)
        except yaml.YAMLError as exc:
            print(exc)
    
    return data


def export_to_tgf(data: dict) -> None:
    """ 
    Translates and exports the yaml network configuration file
        to Trivial Graph Format file (.tgf)
    """
    output_file = open("output_file.tgf", "w")
    
    #Writting nodes to the file
    for interface in data['network']['ethernets']:
        if "H" in interface:
            node_type = "Hub"
        if "sw" in interface:
            node_type = "Switch"
        if "r" in interface:
            node_type = "Router"
        if "pc" in interface:
            node_type = "Client_PC"
        if "sr" in interface:
            node_type = "Server_PC"

        output_file.write(f"{interface} ~ {{'node_type' : '{node_type}'}};\n")
        nodes[interface] = node_type
    
    #Nodes from edges seperator
    output_file.write("#\n")
    
    #Writing edges to the file
    for bond in data['network']['bonds']:
        left_end = data['network']['bonds'][bond]['interfaces'][0]
        right_end = data['network']['bonds'][bond]['interfaces'][1]

        left_end_type = nodes[left_end]
        right_end_type = nodes[right_end]
        
        
        link['link_ID']= '1'
        link['left_end'] = copy.deepcopy(node_type_interfaces[left_end_type])
        link['right_end'] = copy.deepcopy(node_type_interfaces[right_end_type])
        link['capacity'] = '100'
        link['latency'] = '1'

        for node_type, nodes_end, iface in zip([left_end_type, right_end_type], ['left_end', 'right_end'], [left_end, right_end]):
            
            if node_type == 'Hub':
                link[nodes_end]['if_id'] = iface
            
            if node_type == 'Switch':
                link['nodes_end']['if_id'] = iface
                link['nodes_end']['mac'] = data['network']['ethernets'][iface]['macaddress']

            if node_type == 'Router':

                link[nodes_end]['if_id'] = iface
                link[nodes_end]['mac'] = data['network']['ethernets'][iface]['macaddress']
                link[nodes_end]['ip'] = data['network']['ethernets'][iface]['addresses'].split('/')[0]
                link[nodes_end]['mask'] = str(IPNetwork(data['network']['ethernets'][iface]['addresses']).netmask)
                link[nodes_end]['gateway'] = data['network']['ethernets'][iface]['gateway4']
                link[nodes_end]['dns'] = data['network']['ethernets'][iface]['nameservers']['addresses'][0]

                #See if it is a NAT or not
                if IPAddress(link[nodes_end]['ip']).is_private():
                    nat = 'enabled'
                else:
                    nat = 'disabled'
                link[nodes_end]['nat'] = nat

            
            #Client PC and Server PC have the same interface object
            if node_type in {"Client_PC", "Server_PC"}:
                link[nodes_end]['if_id'] = iface
                link[nodes_end]['mac'] = data['network']['ethernets'][iface]['macaddress']
                link[nodes_end]['ip'] = data['network']['ethernets'][iface]['addresses'].split('/')[0]
                link[nodes_end]['mask'] = str(IPNetwork(data['network']['ethernets'][iface]['addresses']).netmask)
                link[nodes_end]['gateway'] = data['network']['ethernets'][iface]['gateway4']
                link[nodes_end]['dns'] = data['network']['ethernets'][iface]['nameservers']['addresses'][0]


        output_file.write(f"{left_end} {right_end} ~ {'{'}\n")
        for attribute in link:
            if attribute in {'left_end', 'right_end'}:
                output_file.write(f"{TAB}'{str(attribute)}' : {link[attribute]}")
            else:
                output_file.write(f"{TAB}'{str(attribute)}' : '{link[attribute]}'")

            if attribute != "latency":
                output_file.write(",\n")
            else:
                output_file.write("\n};\n")
                
    output_file.close() #TODO maybe better handling to file
        

    


def main():
    data = parse_net_config()
    export_to_tgf(data)


if __name__ == "__main__":
    main()