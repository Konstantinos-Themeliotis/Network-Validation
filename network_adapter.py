class Adapter() : 
    
    #Constructor
    def __init__(self, MAC,Gateway) :
        self.MAC = MAC
        self.Gateway = Gateway
        
    #Adapter Object Equalizer - called when self == other 
    def __eq__(self, other): 
        if not isinstance(other, Adapter):
            #Do not attempt to compare against unrelated types
            return NotImplemented
        
        #compare the rest of the attributes if needed - TODO 
        return self.MAC == other.MAC
    
    #Prints the Adapters attributes
    def __str__(self):
        return f"MAC adress:  {self.MAC} \n Gateway: {self.Gateway} \n -----------------"

class L3SwitchAdapter(Adapter):
    
    def __init__(self, MAC, IP, Mask, Gateway):
        super().__init__(MAC,Gateway)
        self.IP = IP
        self.Mask = Mask

    def __str__(self):
        return f"MAC adress:  {self.MAC} \n IP adress: {self.IP} \n Subnet Mask: {self.Mask} \n Gateway: {self.Gateway} \n-----------------"

class L3RouterAdapter(L3SwitchAdapter):
    
    def __init__(self, MAC, IP, Mask, Gateway, NAT):
        super().__init__(MAC, IP, Mask, Gateway)
        self.NAT = NAT

    def __str__(self):
        return f"MAC adress:  {self.MAC} \n IP adress: {self.IP} \n Subnet Mask: {self.Mask} \n Gateway: {self.Gateway} \n NAT: {self.NAT} \n-----------------"

class L7Adapter(L3SwitchAdapter):
    
    def __init__(self, MAC, IP, Mask, Gateway, DNS):
        super().__init__(MAC, IP, Mask, Gateway)
        self.DNS = DNS
    
    def __str__(self):
        return f"MAC adress:  {self.MAC} \n IP adress: {self.IP} \n Subnet Mask: {self.Mask} \n Gateway: {self.Gateway} \n DNS: {self.DNS} \n-----------------"



'''
    -Layer 1:
        -Hub
    -Layer 2:
        -L2 Switch
    -Layer 3:
        -L3 Switch
    -Layer 3-Nat
        -Router
    -Layer 7: 
        Client PC
        Server PC
'''
