class Adapter() : 
    
    #Constructor
    def __init__(self, MAC) :
        self.MAC = MAC
    
    #Adapter Object Equalizer
    def __eq__(self, other): 
        if not isinstance(other, Adapter):
            #Do not attempt to compare against unrelated types
            return NotImplemented
        
        #compare the rest of the attributes - TODO 
        return self.MAC == other.MAC