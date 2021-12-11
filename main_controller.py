import network_validation as nv
import device_configuration as dc
#import networkx as nx

# Current example
EXAMPLE = 'example_4'


def main():
    print("\n")
    
    # Start the device configuration
    dc.start_device_configuration(EXAMPLE)
        
    # Start the network validation
    nv.start_network_validation(EXAMPLE)


if __name__ == '__main__':
    main()