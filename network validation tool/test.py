import tgf_parser as tgf
import os

current_directory_path = os.path.dirname(os.path.realpath(__file__))
path = current_directory_path + "\\" + "topologies" + "\\" +"topology_0"
filename = "net_topology_0_def.tgf"

parser = tgf.Def_TGF_Parser(path, filename)
nodes, edges = parser.parse_network_topology()

