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


class Adapter() : 
    
    #Constructor
    def __init__(self, MAC) :
        self.MAC = MAC
        
    #Adapter Object Equalizer - called when self == other 
    def __eq__(self, other): 
        if not isinstance(other, Adapter):
            
            #Do not attempt to compare against unrelated object types
            return NotImplemented
        
        return self.MAC == other.MAC
    
    #Prints the Adapters attributes
    def __str__(self):
        return f"MAC address:  {self.MAC} \n -----------------"



class PCAdapter(Adapter):
    
    def __init__(self, MAC, IP, Mask, Gateway, DNS):
        super().__init__(MAC)
        self.IP = IP
        self.Mask = Mask
        self.Gateway = Gateway
        self.DNS = DNS

    def __str__(self):
        return f"MAC address:  {self.MAC} \n IP address: {self.IP} \n Subnet Mask: {self.Mask} \n Gateway: {self.Gateway} \n DNS: {self.DNS} \n \n-----------------"


class RouterAdapter(Adapter):
    
    def __init__(self, MAC, IP, Mask, Gateway, DNS, NAT,private_IP):
        super().__init__(MAC)
        self.IP = IP
        self.Mask = Mask
        self.Gateway = Gateway
        self.DNS = DNS
        self.NAT = NAT    
        if NAT == 'enabled':
            self.public_IP = IP
            self.private_IP = private_IP


    
    def __str__(self):
        return f"MAC address:  {self.MAC} \n IP address: {self.IP} \n Subnet Mask: {self.Mask} \n Gateway: {self.Gateway} \n DNS: {self.DNS} \n NAT: {self.NAT} \n-----------------"



