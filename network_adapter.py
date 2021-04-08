class Adapter() : 
    
    #Constructor
    def __init__(self, MAC, IP, Mask, Gateway, DNS) :
        self.MAC = MAC
        self.IP = IP
        self.Mask = Mask
        self.Gateway = Gateway
        self.DNS = DNS

    #Adapter Object Equalizer
    def __eq__(self, other): 
        if not isinstance(other, Adapter):
            #Do not attempt to compare against unrelated types
            return NotImplemented
        
        #compare the rest of the attributes if needed - TODO 
        return self.MAC == other.MAC