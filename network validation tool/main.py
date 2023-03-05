""" TODO: Description """

import network_validation as nv
import device_configuration as dc

# Example to run
TOPOLOGY = 'topology_2'


def main():
    print(f"\n ----- Running network topology: '{TOPOLOGY}' -----\n")

    # Start the device configuration
    dc.start_device_configuration(TOPOLOGY)
        
    # Start the network validation
    nv.start_network_validation(TOPOLOGY)

    print(f"\n ----- End of running: '{TOPOLOGY}' -----\n")

if __name__ == '__main__':
    main()