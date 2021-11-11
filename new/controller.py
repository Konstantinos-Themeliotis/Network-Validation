import network_validation as nv
import network_configuration as nc

# Current example
EXAMPLE = 'example_2'


def main():
    
    # Start the device configuration
    nc.main(EXAMPLE)
    
    # Start the network validation
    nv.main(EXAMPLE)


if __name__ == '__main__':
    main()