""" TODO: Description """


from os import error
from netaddr import *
import yaml
import re

TAB = "    "

# Basic file format
config_file_format = {'network':{'version' : 2, 'renderer' : 'networkd', 'ethernets' : {}}}

# Different interfaces
l2_interface = {"macaddress"}
pc_interface = {"macaddress", "addresses", "gateway4", "nameservers"}
router_interface = {"macaddress", "nat", "addresses", "gateway4", "nameservers"}

# Maps node type with the interface attributes
node_interface_map = {'Switch': l2_interface, "Client_PC": pc_interface, "Server_PC": pc_interface, "Router": router_interface}
 

def print_error_msg(filename: str, error_msg: str) -> None:
    """ Prints an error message and exits"""
    print(f"-Configuration file error at file: '{filename}' :\n\n{TAB}-{error_msg}")
    exit()


def validate_config_format(filename: str, config_data: dict) -> None:
    """ Validate the base format attributes of the configuration file"""
    
    if 'network' not in config_data:
        error_msg = f"Attribute Error: File must start with the key 'network'" 
        print_error_msg(filename, error_msg)
    
    for attr in config_file_format['network']:
        if attr not in config_data['network']:
            error_msg = f"Attribute Error: Attribute '{attr} was not found!'"
            print_error_msg(filename, error_msg)
    
    # Network config format version 2 is used
    if config_data['network']['version'] != config_file_format['network']['version']:
        error_msg = "Attribute Value Error: The current supported format is 'version 2' "
        print_error_msg(filename, error_msg)        
   
    # networkd renderer is used
    if config_data['network']['renderer'] != config_file_format['network']['renderer']:
        error_msg = "Attribute Value Error: This kind of renderer is not supported"
        print_error_msg(filename, error_msg)

    # Must be dict otherwise no interface exists
    if not isinstance(config_data['network']['ethernets'], type(config_file_format['network']['ethernets'])):
        error_msg = "Attribute error: No ethernet device found!"
        print_error_msg(filename, error_msg)


def validate_interfaces(filename: str, config_data: dict, node_type: str) -> None:
    """ Validate the interfaces defined in the configuration file"""
    
    def validate_interface_attr(interface: str) -> None:
        """ Validate, accordingly the node/interface type if it
            has the right attribues
        """
        
        missing_attr = node_interface_map[node_type] - set(config_data['network']['ethernets'][interface])
       
        if missing_attr:
            error_msg = f"Attribute Error: {missing_attr} is missing from interface: {interface}"
            print_error_msg(filename, error_msg)

        if node_type in {"Client_PC", "Server_PC", "Router"}:
            if 'addresses' not in config_data['network']['ethernets'][interface]['nameservers']:
                error_msg = f"Attribute Error: DNS field 'addresses' is missing from interface {interface}"
                print_error_msg(filename, error_msg)
            
            if node_type == 'Router':
                if 'status' not in config_data['network']['ethernets'][interface]['nat']:
                    error_msg = f"Attribute Error: NAT 'status' field is missing from interface {interface}"
                    print_error_msg(filename, error_msg)

                if 'public_ip' not in config_data['network']['ethernets'][interface]['nat']:
                    error_msg = f"Attribute Error: NAT 'public_ip' field is missing from interface {interface}"
                    print_error_msg(filename, error_msg)
                
                if 'rt' not in config_data['network']['ethernets']:
                    error_msg = "Device Error: No routing table is defined in file."
                    print_error_msg(filename, error_msg)


    def validate_interface_values(interface: str) -> None:
        """Validate each interface values"""
        
        if node_type == 'Hub':
            # Nothing to do here
            pass
        
        elif node_type == 'Switch': 
            mac = config_data['network']['ethernets'][interface]['macaddress']
            if not is_valid_mac(mac):
                error_msg = f"Value error: {mac} at interface: {interface} is not a valid mac address"
                print_error_msg(filename, error_msg)

        elif node_type in {"Client_PC", "Server_PC", "Router"}:
            
            # Extract the values from the config data
            mac = config_data['network']['ethernets'][interface]['macaddress']
            ip = config_data['network']['ethernets'][interface]['addresses'].split('/')[0]
            mask = config_data['network']['ethernets'][interface]['addresses'].split('/')[1]
            gateway = config_data['network']['ethernets'][interface]['gateway4']
            dns = config_data['network']['ethernets'][interface]['nameservers']['addresses'][0]

            # Check if mac address is valid mac address value
            if not is_valid_mac(mac):
                error_msg = f"Value error: {mac}, at interface: {interface}, is not a valid mac address"
                print_error_msg(filename, error_msg)
            
            # Check if ip address is valid ip address value
            valid_ip, ip_error_msg = is_valid_ip(ip)
            if not valid_ip:
                error_msg = f"Value error: {ip}, at interface: {interface} is not a valid ip address.\n{TAB}{ip_error_msg}"
                print_error_msg(filename, error_msg)
            
            # Check if mask is valid mask value
            if not is_valid_mask(mask):
                error_msg = f"Value error: /{mask}, at interface: {interface} is not a valid network mask"
                print_error_msg(filename, error_msg)

            # Check if gateway address is valid ip address value
            valid_ip, ip_error_msg = is_valid_ip(gateway)
            if not valid_ip:
                error_msg = f"Value error: {gateway}, at interface: {interface} is not a valid gateway address. \n{TAB}{ip_error_msg}"
                print_error_msg(filename, error_msg)

            # Check if dns address is valid dns address value
            valid_ip, ip_error_msg = is_valid_ip(dns)
            if not valid_ip:
                error_msg = f"Value error: {dns}, at interface: {interface} is not a valid dns address. \n{TAB}{ip_error_msg}"
                print_error_msg(filename, error_msg)

            if node_type == "Router": 
                
                nat = config_data['network']['ethernets'][interface]['nat']['status']
                public_ip = config_data['network']['ethernets'][interface]['nat']['public_ip'].split('/')[0]

                # Check if nat option is valid option
                if nat not in {'enabled', "disabled"}:
                    error_msg = f"Value error: {nat}, at interface: {interface} is not a valid nat option"
                    print_error_msg(filename, error_msg)
                
                # Check if public ip address in a NAT is valid ip address value
                valid_ip, ip_error_msg = is_valid_ip(public_ip)
                if not valid_ip:
                    error_msg = f"Value error: '{public_ip}', at interface: {interface} is not a valid ip address. \n{TAB}{ip_error_msg}"
                    print_error_msg(filename, error_msg)
        
                # Check if public, private ip are a valid public or private ip
                public_ip = IPAddress(public_ip)
                private_ip =  IPAddress(ip)
                
                if nat == 'enabled':
                    if public_ip.is_private():
                        error_msg = f"Value Error: '{public_ip}', at interface: {interface}, is not a valid public ip "
                        print_error_msg(filename, error_msg)
                    if not private_ip.is_private():
                        error_msg = f"Value Error: '{private_ip}, at interface: {interface}, is not a valid private ip"
                        print_error_msg(filename, error_msg)

                else: # Nat disabled
                    public_ip = private_ip                    
                    if public_ip.is_private():
                        error_msg = f"Value Error: '{public_ip}', at interface: {interface}, is not a valid public ip address"
                        print_error_msg(filename, error_msg)



        else:
            error_msg = f"Error: {node_type} is not a valid node type"
            print_error_msg(filename, error_msg)


    def validate_routing_table_attr(interface: str) -> None:
        """ Validates the interface that stores the routers routing table"""
        
        if 'routes' not in config_data['network']['ethernets'][interface]:
            error_msg = "Attribute Error: 'routes' key is missing from routing interface "
            print_error_msg(filename, error_msg)
        
        if 'to' not in config_data['network']['ethernets']['rt']['routes']:
            error_msg = "Attribute Error: 'to' key is missing from routing interface "
            print_error_msg(filename, error_msg)
        
        if 'via' not in config_data['network']['ethernets']['rt']['routes']:
            error_msg = "Attribute Error: 'via' key is missing from routing interface "
            print_error_msg(filename, error_msg)
        
        to_entries_size = len(config_data['network']['ethernets']['rt']['routes']['to'])
        via_entries_size =  len(config_data['network']['ethernets']['rt']['routes']['via'])
        
        if to_entries_size != via_entries_size:
            error_msg = "Attribute Error: Entries are missing from routing table"
            print_error_msg(filename, error_msg)


    def validate_routing_table_values(interface: str) -> None:
            """ Validate routing table values"""

            to_list = config_data['network']['ethernets']['rt']['routes']['to']
            via_list = config_data['network']['ethernets']['rt']['routes']['via']

            for addr in to_list:
                if addr != '0.0.0.0':
                    
                    ip = addr.split('/')[0]
                    mask = addr.split('/')[1]
                    
                    valid_ip, ip_error_msg = is_valid_ip(ip)
                    if not valid_ip:
                        error_msg = f"Value Error: {addr} address at routing table -to- list is not a valid ip address.\n{TAB}{ip_error_msg}"
                        print_error_msg(filename, error_msg)
                    
                    if not is_valid_mask(mask): 
                        error_msg = f"Value Error: '/{mask}' at address: '{addr}', at routing tables -to- list, is not a valid network mask."
                        error_msg += " A Network mask must be an integer number in range 0-32"
                        print_error_msg(filename, error_msg)
            
            for addr in via_list:
                if addr != '0.0.0.0':
                    valid_ip, ip_error_msg = is_valid_ip(addr)
                    if not valid_ip:
                        error_msg = f"Value Error: {addr} address at routing tables -via- list is not a valid ip address.\n{TAB}{ip_error_msg} "
                        print_error_msg(filename, error_msg)
            

    # Start
    for interface in config_data['network']['ethernets']:
        
        # Validate the routing table interface
        if interface == 'rt':
            validate_routing_table_attr(interface)
            validate_routing_table_values(interface)
            continue
        
        # Validate each interfaces attributes and values
        validate_interface_attr(interface)
        validate_interface_values(interface)


def is_valid_mac(mac: str) -> bool:
    """ Checks if an address is a valid mac address
    
        -A valid mac address consists of 12 hexadecimal digits, organized
        in 6 pairs and those pairs are seperated by hyphen (-)
    
    """
    
    return bool(re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()))


def is_valid_ip(ip: str) -> bool:
    """ Checks if an address is a valid ip address 
        
        -A valid ip address has length of 32 bit formatted as four 8-bit fields 
        separated by periods.Each 8-bit field represents a byte of the ip address
        Every 8-bit field is written as an integer number of range 0-255
        
        -Eg:
            192.168.1.20 is a valid ip address
            192.168.1.260 in NOT a valid ip address -260 > 255
            192.168.001.20 in NOT a valid ip address -leading zeros in 3rd field
    
    """
        
    addr_fields = ip.split(".")
    
    # Ip should be four 8-bit fields and all should be decimal numbers
    if len(addr_fields) != 4 or not all((field.isdecimal()) for field in addr_fields) :
        error_msg = " IP address consists of 4 address fields, decimal integer numbers in range 0-255"
        return False, error_msg    
    
    for field in addr_fields:
        
        # Every field  must be a decimal interger number in range 0-255 
        if not (int(field) >= 0 and int(field) <= 255):
            error_msg = " IP address fields must be decimal integer numbers in range 0-255" 
            return False, error_msg
        
        if not (len(field.lstrip('0')) == len(field) or len(field) == 1):
            error_msg = " No leading zeros in IP address fields allowed!"
            return False, error_msg
    
    return True, ""
        

def is_valid_mask(mask: str) -> bool: 
    """ Checks if an address is a valid network mask"""
    return int(mask) >= 0 and int(mask) <= 32 


def main(filename: str, config_data, node_type: str)-> None:
    """ Main function"""
    
    validate_config_format(filename, config_data)
    validate_interfaces(filename, config_data, node_type)


def start_config_validation(filename: str, config_data: dict, node_type: str) -> None:
    """ The function/interface that is called from the device configuration file"""
    
    main(filename, config_data, node_type)


if __name__ == '__main__':
    print("Warning: This file is called from the device configruation file, doesnt run on its own!")
