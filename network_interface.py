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
    def __init__(self, attr: dict):
        self.if_id = attr["if_id"]
    
    def __eq__(self, other):
        if not isinstance(other, Interface):
            return NotImplemented
        
        return self.if_id == other.if_id


class L2Interface(Interface):
    def __init__(self, attr: dict):
        super().__init__(attr)
        self.mac = EUI(attr['mac'])
    
    def __str__(self):
        output = f"Layer 2 Interface: {self.if_id}\n"
        output += f"MAC address. . . . . . . . . . : {str(self.mac)}\n"
    

class L3Interface(Interface):
    def __init__(self, attr: dict):
        super().__init__(attr)
        self.mac = EUI(attr['mac'])
        self.ipv4 = IPAddress(attr['ipv4'])
        self.mask = IPAddress(attr['mask'])
        self.gateway = IPAddress(attr['gateway'])
        self.dns = IPAddress(attr['dns'])
    
    def __str__(self):
        output = f"-Inteface {self.if_id}-\n"
        output += f"MAC address . . . . . . . . . . . : {str(self.mac)}\n"
        output += f"IPv4 address. . . . . . . . . . . : {str(self.ipv4)}\n"
        output += f"Subnet Mask . . . . . . . . . . . : {str(self.mask)}\n"
        output += f"Gateway . . . . . . . . . . . . . : {str(self.gateway)}\n"
        output += f"DNS . . . . . . . . . . . . . . . : {str(self.dns)}\n"
        return output


class RouterInterface(L3Interface):
    def __init__(self, attr: dict):
        super().__init__(attr)
        self.nat = attr['nat']
    
    def __str__(self):
        return super(RouterInterface, self).__str__() + str(self.nat)



class PcInterface(L3Interface):
    def __init__(self, attr: dict):
        super().__init__(attr)
    
    def __str__(self): 
        return super(PcInterface, self).__str__()

