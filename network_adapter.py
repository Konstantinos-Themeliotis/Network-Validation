'''
    -Layer 1: 
        -Hub -> No adapter object-No needed
    
    -Layer 2:
        -Switch -> Adapter()
    
    -Layer 3:    
            -Router ->RouterAdapter(Adapter2)

    -Layer 7: 
        -Client PC ->L7Adapter(L3Adapter): MAC, IP, Mask, Gateway, DNS
        
        -Server PC: ->L7Adapter(L3Adapter): MAC, IP, Mask, Gateway, DNS 
'''
from netaddr import *


class Adapter() : 
    #Constructor
    def __init__(self, MAC) :
        self.MAC = EUI(MAC)
        
    #Adapter Object Equalizer 
    def __eq__(self, other): 
        if not isinstance(other, Adapter):
            return NotImplemented
        
        return self.MAC == other.MAC
    
    def __str__(self):
        return f"MAC address. . . . . . . . . . : {str(self.MAC)}\n"


class PCAdapter(Adapter):
    def __init__(self, MAC, IP, Mask, Gateway, DNS):
        super().__init__(MAC)
        self.IP = IPAddress(IP)
        self.Mask = IPAddress(Mask)
        self.Gateway = IPAddress(Gateway)
        self.DNS = IPAddress(DNS)
    
    def __str__(self):
        output = f"MAC address . . . . . . . . . . . : {str(self.MAC)}\n"
        output += f"IP address . . . . . . . . . . . : {str(self.IP)}\n"
        output += f"Subnet Mask . . . . . . . . . . . : {str(self.Mask)}\n"
        output += f"Gateway . . . . . . . . . . . . . : {str(self.Gateway)}\n"
        output += f"DNS . . . . . . . . . . . . . . . : {str(self.DNS)}\n"
        return output


class RouterAdapter(Adapter):
    def __init__(self, MAC, IP, Mask, Gateway, DNS, NAT, private_IP):
        super().__init__(MAC)
        self.IP = IPAddress(IP)
        self.Mask = IPAddress(Mask)
        self.Gateway = IPAddress(Gateway)
        self.DNS = IPAddress(DNS)
        self.NAT = NAT    
        
        if NAT == 'enabled':
            self.public_IP = IPAddress(IP)
            self.private_IP = IPAddress(private_IP)

    def __str__(self) -> str:
        output = f"MAC address . . . . . . . . . . . : {str(self.MAC)}\n"
        output += f"IP address. . . . . . . . . . . . : {str(self.IP)}\n"
        output += f"Subnet Mask . . . . . . . . . . . : {str(self.Mask)}\n"
        output += f"Gateway . . . . . . . . . . . . . : {str(self.Gateway)}\n"
        output += f"DNS . . . . . . . . . . . . . . . : {str(self.DNS)}\n"
        output += f"NAT . . . . . . . . . . . . . . . : {str(self.NAT)}\n"
        return output        