"""
    Classes that implement network interfaces

                            Interface:Hub
                                |
                                |
                -------------------------------------
                |                                   |
                |                                   |
                |                                   |
            L2Interface:Switch                  L3Interface
                                                    |
                                                    |
                                        -----------------------         
                                        |                     |
                                        |                     |
                            RouterInterface:Router       PcInterface: Client PC || Server PC


"""     


from netaddr import *
 

class Interface():
    """ Base class of a network Interface. """ 

    def __init__(self, attr: dict) -> None:
        self.if_id = attr["if_id"]
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, Interface):
            return NotImplemented
        
        return self.if_id == other.if_id


class L2Interface(Interface):
    """ Network layer 2 interface of a switch """

    def __init__(self, attr: dict) -> None:
        super().__init__(attr)
        self.mac = EUI(attr['mac'])
    
    def __str__(self) -> str:
        output = f"Layer 2 Interface: {self.if_id}\n"
        output += f"MAC address. . . . . . . . . . : {str(self.mac)}\n"
        return output
    

class L3Interface(Interface):
    """ Network layer 3 interface""" 

    def __init__(self, attr: dict) -> None:
        super().__init__(attr)
        self.mac = EUI(attr['mac'])
        self.ip = IPAddress(attr['ip'])
        self.mask = IPAddress(attr['mask'])
        self.gateway = IPAddress(attr['gateway'])
        self.dns = IPAddress(attr['dns'])
    
    def __str__(self) -> str:
        output = f"-Inteface {self.if_id}-\n"
        output += f"MAC address . . . . . . . . . . . : {str(self.mac)}\n"
        output += f"IPv4 address. . . . . . . . . . . : {str(self.ip)}\n"
        output += f"Subnet Mask . . . . . . . . . . . : {str(self.mask)}\n"
        output += f"Gateway . . . . . . . . . . . . . : {str(self.gateway)}\n"
        output += f"DNS . . . . . . . . . . . . . . . : {str(self.dns)}\n"
        return output


class RouterInterface(L3Interface):
    """ Network layer 3 Router interface"""

    def __init__(self, attr: dict) -> None:
        super().__init__(attr)
        self.nat = attr['nat']
        self.public_ip = IPAddress(attr['public_ip'].split('/')[0])
    
    def __str__(self) -> str:
        output = f"NAT . . . . . . . . . . . . . . . : {self.nat}"
        output += f"Public IP. . . . . . . . . . . . : {self.public_ip}"
        return super(RouterInterface, self).__str__() + output



class PcInterface(L3Interface):
    """ Netwrok layer 3 Client PC or Server PC inteface """ 

    def __init__(self, attr: dict) -> None:
        super().__init__(attr)
    
    def __str__(self) -> str: 
        return super(PcInterface, self).__str__()

